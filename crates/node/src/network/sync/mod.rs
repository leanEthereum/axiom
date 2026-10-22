//! Catching up: fetching blocks, their data, and their payloads from peers that are ahead.
//!
//! Range sync moves forward from the head; backfill moves backward from the stored history.

mod backfill;

use std::{collections::HashMap, sync::Arc};

use axiom_das::{ColumnSidecar, PayloadColumnSidecar};
use axiom_fork_choice::ForkChoiceError;
use axiom_gossip::CheckedBlob;
use axiom_kzg::Kzg;
use axiom_p2p::{
    PeerId,
    eth::reqresp::{Protocol, ResponseChunk, ResponseCode, Status},
    swarm::{NetworkError, NetworkHandle, RequestId},
};
use axiom_ssz::{List, Root, Ssz};
use axiom_types::{
    BlobData, ChainConfig, ColumnIndex, ForkDigest, Preset, Slot, combined,
    deneb::BlobSidecar,
    gloas::{ExecutionPayloadBid, SignedExecutionPayloadEnvelope},
};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task,
};
use tracing::{debug, info, warn};

pub(crate) use self::backfill::{BackfillOutcome, BackfillSync};
use super::{
    forks::ForkDigests,
    requests::{BlocksByRangeRequest, ColumnsByRangeRequest, SlotRangeRequest},
};
use crate::{ChainError, ChainHandle, ExecutionLayer};

/// Slots fetched per batch.
///
/// One epoch on mainnet: small enough to retry cheaply, large enough to amortize the round trip.
const BATCH_SLOTS: u64 = 32;

/// Failed batches after which a peer is no longer asked.
///
/// A peer that times out or answers with errors this often is useless for sync, if not hostile.
const MAX_STRIKES: u32 = 3;

/// What one request of a batch fetches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fetch {
    /// Blocks by range.
    Blocks,
    /// Blob sidecars by range, Deneb and Electra.
    Blobs,
    /// Sampled columns by range, from Fulu on.
    Columns,
    /// Payload envelopes by range, from Gloas on.
    Envelopes,
}

impl Fetch {
    /// What a batch of one fork's range fetches, blocks first.
    ///
    /// Data older than the retention window is not asked for: peers may have dropped it.
    fn for_range<P: Preset>(
        config: &ChainConfig,
        start: Slot,
        current: Slot,
        sampled: &[ColumnIndex],
    ) -> Vec<Self> {
        let data = config.fork_at(start.epoch::<P>()).blob_data();
        let mut fetches = vec![Self::Blocks];
        if Self::is_retained::<P>(config, start, current) {
            if data == BlobData::BlobSidecars {
                fetches.push(Self::Blobs);
            }
            if data.is_columns() && !sampled.is_empty() {
                fetches.push(Self::Columns);
            }
        }
        // Payloads come apart from their blocks from Gloas on, whatever their age.
        if data == BlobData::PayloadColumns {
            fetches.push(Self::Envelopes);
        }
        fetches
    }

    /// Whether peers still serve the blob data of a slot at the current slot.
    ///
    /// See the retention notes of the Deneb and Fulu p2p specs.
    fn is_retained<P: Preset>(config: &ChainConfig, slot: Slot, current: Slot) -> bool {
        let data = config.fork_at(slot.epoch::<P>()).blob_data();
        let window = config.blob_retention_epochs(data);
        slot.epoch::<P>().0.saturating_add(window) >= current.epoch::<P>().0
    }

    /// The method that fetches it.
    const fn protocol(self) -> Protocol {
        match self {
            Self::Blocks => Protocol::BeaconBlocksByRangeV2,
            Self::Blobs => Protocol::BlobSidecarsByRangeV1,
            Self::Columns => Protocol::DataColumnSidecarsByRangeV1,
            Self::Envelopes => Protocol::ExecutionPayloadEnvelopesByRangeV1,
        }
    }
}

/// What a batch received, item by item.
#[derive(Debug)]
struct Received<P: Preset> {
    /// Blocks, oldest first.
    blocks: Vec<combined::SignedBeaconBlock<P>>,
    /// Blob sidecars.
    blobs: Vec<BlobSidecar<P>>,
    /// Columns.
    columns: Vec<combined::DataColumnSidecar<P>>,
    /// Payload envelopes.
    envelopes: Vec<SignedExecutionPayloadEnvelope<P>>,
}

impl<P: Preset> Default for Received<P> {
    fn default() -> Self {
        Self {
            blocks: Vec::new(),
            blobs: Vec::new(),
            columns: Vec::new(),
            envelopes: Vec::new(),
        }
    }
}

impl<P: Preset> Received<P> {
    /// Checks the batch's blob data: blobs against their blocks, columns against their commitments.
    ///
    /// Every blob must open its commitment and be included in its block.
    /// Every Fulu column must be well formed, included, and open its commitments.
    /// Every Gloas column must open the commitments of its block's bid, a block of the batch.
    fn verify(&self, config: &ChainConfig) -> Result<(), String> {
        let kzg = Kzg::mainnet();
        for blob in &self.blobs {
            let checked = CheckedBlob(blob);
            if !checked.has_valid_inclusion_proof() || !checked.has_valid_kzg_proof(kzg) {
                return Err(format!(
                    "blob {} of the block at slot {} does not verify",
                    blob.index.0, blob.signed_block_header.message.slot
                ));
            }
        }
        for column in &self.columns {
            let checked = match column {
                combined::DataColumnSidecar::Fulu(sidecar) => {
                    let sidecar = ColumnSidecar(sidecar);
                    sidecar
                        .verify_structure(config)
                        .and_then(|()| sidecar.verify_inclusion_proof())
                        .and_then(|()| sidecar.verify_kzg_proofs(kzg))
                }
                combined::DataColumnSidecar::Gloas(sidecar) => {
                    let root = sidecar.beacon_block_root;
                    let Some(bid) = self.bid(&root) else {
                        return Err(format!(
                            "column {} names block {root} outside the batch",
                            sidecar.index.0
                        ));
                    };
                    PayloadColumnSidecar(sidecar).verify(&bid.blob_kzg_commitments, kzg)
                }
            };
            checked.map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// The bid of the batch's Gloas block with a root.
    fn bid(&self, root: &Root) -> Option<&ExecutionPayloadBid> {
        self.blocks.iter().find_map(|block| match block {
            combined::SignedBeaconBlock::Gloas(signed)
                if signed.message.hash_tree_root() == *root =>
            {
                Some(&signed.message.body.signed_execution_payload_bid.message)
            }
            _ => None,
        })
    }
}

/// One range of one fork, being fetched from one peer.
#[derive(Debug)]
struct Batch<P: Preset> {
    /// The peer serving it.
    peer: PeerId,
    /// First slot of the range.
    start: Slot,
    /// Slots in the range.
    count: u64,
    /// The batch's requests, and what each fetches.
    requests: Vec<(RequestId, Fetch)>,
    /// Requests still streaming.
    open: usize,
    /// Why the peer's answer is unusable, if it is.
    fault: Option<String>,
    /// Whether the peer answered with an error.
    failed: bool,
    /// What arrived so far.
    received: Received<P>,
}

impl<P: Preset> Batch<P> {
    /// Sends the requests of a batch to a peer.
    async fn send(
        network: &NetworkHandle,
        peer: PeerId,
        range: (Slot, u64),
        fetches: &[Fetch],
        sampled: &[ColumnIndex],
    ) -> Result<Self, NetworkError> {
        let (start, count) = range;
        let mut requests = Vec::new();
        for fetch in fetches {
            let body = match fetch {
                Fetch::Blocks => BlocksByRangeRequest {
                    start_slot: start,
                    count,
                    step: 1,
                }
                .encode(),
                Fetch::Blobs | Fetch::Envelopes => SlotRangeRequest {
                    start_slot: start,
                    count,
                }
                .encode(),
                Fetch::Columns => ColumnsByRangeRequest::<P> {
                    start_slot: start,
                    count,
                    // Sampled columns never exceed the column count, so the list always fits.
                    columns: List::try_from(sampled.to_vec()).unwrap_or_default(),
                }
                .encode(),
            };
            let id = network
                .send_request(peer.clone(), fetch.protocol(), body)
                .await?;
            requests.push((id, *fetch));
        }
        debug!(%peer, start = %start, count, ?fetches, "requested batch");
        Ok(Self {
            peer,
            start,
            count,
            open: requests.len(),
            requests,
            fault: None,
            failed: false,
            received: Received::default(),
        })
    }

    /// Whether a request is one of the batch's.
    fn owns(&self, request: RequestId) -> bool {
        self.requests.iter().any(|(id, _)| *id == request)
    }

    /// Takes one response chunk.
    ///
    /// Each item must decode as the fork its slot falls in, under that fork's context bytes.
    /// An item that does not condemns the whole batch, and the peer with it.
    fn on_chunk(
        &mut self,
        config: &ChainConfig,
        forks: &ForkDigests,
        request: RequestId,
        chunk: &ResponseChunk,
    ) {
        if chunk.code != ResponseCode::Success {
            debug!(peer = %self.peer, code = ?chunk.code, "batch request answered with an error");
            self.failed = true;
            return;
        }
        let Some(fetch) = self
            .requests
            .iter()
            .find(|(id, _)| *id == request)
            .map(|(_, fetch)| *fetch)
        else {
            return;
        };
        let context = chunk.context.unwrap_or(ForkDigest([0; 4]));
        if let Err(fault) =
            Self::take(config, forks, fetch, context, &chunk.payload, &mut self.received)
        {
            self.fault.get_or_insert(fault);
        }
    }

    /// Marks one request finished, and tells whether every request has.
    fn on_end(&mut self, request: RequestId) -> bool {
        if self.owns(request) {
            self.open = self.open.saturating_sub(1);
        }
        self.open == 0
    }

    /// Decodes one item in its fork and files it with what the batch received.
    fn take(
        config: &ChainConfig,
        forks: &ForkDigests,
        fetch: Fetch,
        context: ForkDigest,
        payload: &[u8],
        received: &mut Received<P>,
    ) -> Result<(), String> {
        let undecodable = |error| format!("undecodable {fetch:?} item: {error}");
        let slot = match fetch {
            Fetch::Blocks => {
                let block =
                    combined::SignedBeaconBlock::decode_at(payload, config).map_err(undecodable)?;
                let slot = block.slot();
                received.blocks.push(block);
                slot
            }
            Fetch::Blobs => {
                let blob = BlobSidecar::decode(payload).map_err(undecodable)?;
                let slot = blob.signed_block_header.message.slot;
                received.blobs.push(blob);
                slot
            }
            Fetch::Columns => {
                // The context names the column's format; the column's own slot then confirms it.
                let fork = forks
                    .fork_of(context)
                    .ok_or_else(|| format!("unknown context bytes {context:?}"))?;
                let column =
                    combined::DataColumnSidecar::decode(payload, fork).map_err(undecodable)?;
                let slot = column.slot();
                received.columns.push(column);
                slot
            }
            Fetch::Envelopes => {
                let envelope =
                    SignedExecutionPayloadEnvelope::decode(payload).map_err(undecodable)?;
                let slot = Slot(envelope.message.payload.slot_number);
                received.envelopes.push(envelope);
                slot
            }
        };
        let expected = forks.digest_at(slot.epoch::<P>());
        if context != expected {
            return Err(format!(
                "{fetch:?} item at slot {slot} has context {context:?}, expected {expected:?}"
            ));
        }
        Ok(())
    }
}

/// What processing a batch led to.
#[derive(Debug)]
enum Verdict {
    /// Every block imported or waits for data; the range is done.
    Done,
    /// The first block's parent is unknown: the head is on a fork the peer does not share.
    UnknownParent,
    /// The peer served invalid data.
    Invalid(String),
}

/// A processed batch, reported back to the sync loop.
#[derive(Debug)]
pub(crate) struct BatchOutcome {
    /// The peer that served it.
    peer: PeerId,
    /// The slot after the range.
    end: Slot,
    /// What happened.
    verdict: Verdict,
}

/// Range sync: one batch at a time, from the best peer, until the node reaches the network's head.
///
/// # Overview
///
/// 1. Check the peer's status: a wrong fork digest or a head in the future disconnects it.
/// 2. Request a range of one fork: its blocks, and the data and payloads that fork has.
/// 3. A background task checks the data: blob proofs, or column proofs.
/// 4. It then runs the blocks through the engine and imports them, each payload after its block.
///
/// A batch never spans a fork boundary.
/// So every item in it decodes as one fork's container, and one data form applies.
///
/// The batch ends in one of three ways:
///
/// - Done: the cursor moves past the range, empty or not.
/// - Unknown parent: the head is on a dead fork, so the cursor rewinds to finality.
/// - Invalid data: the peer is disconnected.
///
/// A peer that fails a request repeatedly is no longer asked.
/// Processing runs off the network loop, so peers' requests keep being answered meanwhile.
#[derive(Debug)]
pub(crate) struct RangeSync<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for judging payloads.
    execution: Arc<ExecutionLayer>,
    /// The network, for requests.
    network: NetworkHandle,
    /// The fork schedule, which bounds batches and picks what they fetch.
    config: ChainConfig,
    /// The digest each item's context bytes must carry.
    forks: Arc<ForkDigests>,
    /// Latest status of every connected peer that passed the checks.
    peers: HashMap<PeerId, Status>,
    /// Failed batches per peer.
    strikes: HashMap<PeerId, u32>,
    /// The batch being fetched, if any.
    batch: Option<Batch<P>>,
    /// Whether a fetched batch is being processed.
    processing: bool,
    /// The first slot not yet fetched.
    cursor: Slot,
    /// Whether the cursor was moved back to finality, below the head.
    rewound: bool,
    /// Where processing tasks report.
    outcomes: UnboundedSender<BatchOutcome>,
}

impl<P: Preset> RangeSync<P> {
    /// A sync with no peer yet, and the receiver its processing reports to.
    pub(crate) fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        network: NetworkHandle,
        config: ChainConfig,
        forks: Arc<ForkDigests>,
    ) -> (Self, UnboundedReceiver<BatchOutcome>) {
        let (outcomes, receiver) = unbounded_channel();
        let sync = Self {
            chain,
            execution,
            network,
            config,
            forks,
            peers: HashMap::new(),
            strikes: HashMap::new(),
            batch: None,
            processing: false,
            cursor: Slot(0),
            rewound: false,
            outcomes,
        };
        (sync, receiver)
    }

    /// Records a peer's status, after checking it, and starts a batch if the node is behind.
    ///
    /// A peer on another fork, or claiming a head past the clock, is disconnected.
    /// See the status handshake in the phase0 p2p spec.
    pub(crate) async fn on_status(&mut self, peer: PeerId, status: Status) {
        let Ok(current) = self.chain.run(|chain| chain.store().current_slot()).await else {
            return;
        };
        let digest = self.forks.digest_at(current.epoch::<P>());
        // One slot of slack covers the clock disparity at a slot boundary.
        if status.fork_digest != digest || status.head_slot > Slot(current.0 + 1) {
            debug!(%peer, "peer status is on another fork or from the future");
            self.drop_peer(&peer).await;
            return;
        }
        self.peers.insert(peer, status);
        self.advance().await;
    }

    /// Forgets a peer, abandoning its batch.
    pub(crate) async fn on_disconnect(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
        self.strikes.remove(peer);
        if self.batch.as_ref().is_some_and(|batch| batch.peer == *peer) {
            self.batch = None;
            self.advance().await;
        }
    }

    /// Whether a request belongs to the batch being fetched.
    pub(crate) fn owns(&self, request: RequestId) -> bool {
        self.batch.as_ref().is_some_and(|batch| batch.owns(request))
    }

    /// Takes one response chunk of the batch.
    pub(crate) fn on_chunk(&mut self, request: RequestId, chunk: &ResponseChunk) {
        if let Some(batch) = &mut self.batch {
            batch.on_chunk(&self.config, &self.forks, request, chunk);
        }
    }

    /// Marks one of the batch's requests finished, starting processing once all are.
    pub(crate) async fn on_end(&mut self, request: RequestId) {
        if !self.batch.as_mut().is_some_and(|batch| batch.on_end(request)) {
            return;
        }
        let Some(batch) = self.batch.take() else {
            return;
        };
        if batch.failed {
            self.strike(&batch.peer);
            self.advance().await;
            return;
        }
        if let Some(reason) = batch.fault {
            warn!(peer = %batch.peer, %reason, "disconnecting peer for a bad batch");
            self.drop_peer(&batch.peer).await;
            self.advance().await;
            return;
        }
        self.processing = true;
        let worker = BatchWorker {
            chain: self.chain.clone(),
            execution: Arc::clone(&self.execution),
        };
        let outcomes = self.outcomes.clone();
        task::spawn(async move {
            let outcome = worker.process(batch).await;
            // A stopped sync loop has nobody to tell.
            let _stopped = outcomes.send(outcome);
        });
    }

    /// Abandons the batch after a failed request, and tries again.
    pub(crate) async fn on_failure(&mut self, request: RequestId) {
        if !self.owns(request) {
            return;
        }
        if let Some(batch) = self.batch.take() {
            self.strike(&batch.peer);
        }
        self.advance().await;
    }

    /// Takes the result of a processed batch, then fetches the next one.
    pub(crate) async fn on_outcome(&mut self, outcome: BatchOutcome) {
        self.processing = false;
        match outcome.verdict {
            // The range is done even if it held no block: the cursor moves past it.
            Verdict::Done => self.cursor = outcome.end,
            // Already rewound to finality and still disconnected: the peer is on another chain.
            Verdict::UnknownParent if self.rewound => {
                warn!(peer = %outcome.peer, "peer's chain does not reach our finalized block");
                self.drop_peer(&outcome.peer).await;
            }
            Verdict::UnknownParent => {
                // Start again from finality; the fork choice sorts the branches out.
                if let Ok(finalized) = self
                    .chain
                    .run(|chain| chain.head().finalized.epoch.start_slot::<P>())
                    .await
                {
                    info!(slot = %finalized, "range does not connect to the head, rewinding to finality");
                    self.cursor = Slot(finalized.0 + 1);
                    self.rewound = true;
                }
            }
            Verdict::Invalid(reason) => {
                warn!(peer = %outcome.peer, %reason, "disconnecting peer for a bad batch");
                self.drop_peer(&outcome.peer).await;
            }
        }
        self.advance().await;
    }

    /// Starts the next batch if a peer is ahead and nothing is in flight.
    async fn advance(&mut self) {
        if self.batch.is_some() || self.processing {
            return;
        }
        let Ok((head, current, sampled)) = self
            .chain
            .run(|chain| {
                (
                    chain.head().slot,
                    chain.store().current_slot(),
                    chain.custody().iter().copied().collect::<Vec<_>>(),
                )
            })
            .await
        else {
            return;
        };
        // After a rewind the cursor stays behind the head until it passes it again.
        self.rewound &= self.cursor <= head;
        let start = if self.rewound {
            self.cursor
        } else {
            Slot(self.cursor.0.max(head.0 + 1))
        };

        // The usable peer furthest ahead serves the next batch.
        let strikes = &self.strikes;
        let Some((peer, status)) = self
            .peers
            .iter()
            .filter(|(peer, _)| strikes.get(*peer).copied().unwrap_or(0) < MAX_STRIKES)
            .max_by_key(|(_, status)| status.head_slot)
            .map(|(peer, status)| (peer.clone(), *status))
        else {
            return;
        };
        if status.head_slot < start {
            return;
        }
        // A batch stops at the next fork, so all of it decodes and checks under one fork.
        let epoch = start.epoch::<P>();
        let boundary = self.config.next_fork_epoch(epoch).start_slot::<P>();
        let count = BATCH_SLOTS
            .min(status.head_slot.0 - start.0 + 1)
            .min(boundary.0.saturating_sub(start.0).max(1));
        let fetches = Fetch::for_range::<P>(&self.config, start, current, &sampled);
        match Batch::send(&self.network, peer, (start, count), &fetches, &sampled).await {
            Ok(batch) => self.batch = Some(batch),
            Err(error) => warn!(%error, "could not request a batch"),
        }
    }

    /// Counts a failed batch against a peer.
    fn strike(&mut self, peer: &PeerId) {
        *self.strikes.entry(peer.clone()).or_default() += 1;
    }

    /// Stops using a peer and disconnects it.
    async fn drop_peer(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
        self.strikes.insert(peer.clone(), MAX_STRIKES);
        // A disconnect only fails when the network is gone, which ends sync anyway.
        let _stopped = self.network.disconnect(peer.clone()).await;
    }
}

/// Verifies and imports one batch, away from the network loop.
#[derive(Debug)]
struct BatchWorker<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for judging payloads.
    execution: Arc<ExecutionLayer>,
}

impl<P: Preset> BatchWorker<P> {
    /// Data first, so each block is available the moment it is submitted, then blocks in order.
    async fn process(self, batch: Batch<P>) -> BatchOutcome {
        let Batch {
            peer,
            start,
            count,
            received,
            ..
        } = batch;
        let end = Slot(start.0 + count);
        let verdict = self.verdict(received).await;
        BatchOutcome { peer, end, verdict }
    }

    /// Checks and imports the batch's contents.
    async fn verdict(&self, received: Received<P>) -> Verdict {
        let Ok(config) = self.chain.run(|chain| chain.config().clone()).await else {
            return Verdict::Done;
        };
        // KZG checks are CPU-bound, so they run on the blocking pool.
        let checked =
            task::spawn_blocking(move || received.verify(&config).map(|()| received)).await;
        let Received {
            blocks,
            blobs,
            columns,
            envelopes,
        } = match checked {
            Ok(Ok(received)) => received,
            Ok(Err(reason)) => return Verdict::Invalid(reason),
            Err(_) => return Verdict::Done,
        };
        for blob in blobs {
            let blob = Arc::new(blob);
            if let Ok(Err(error)) = self.chain.run(move |chain| chain.submit_blob(blob)).await {
                return Verdict::Invalid(error.to_string());
            }
        }
        for column in columns {
            let column = Arc::new(column);
            if let Ok(Err(error)) = self
                .chain
                .run(move |chain| chain.submit_column(column))
                .await
            {
                return Verdict::Invalid(error.to_string());
            }
        }

        // Each payload follows its block, since the next block may build on it.
        let mut envelopes: HashMap<Root, SignedExecutionPayloadEnvelope<P>> = envelopes
            .into_iter()
            .map(|envelope| (envelope.message.beacon_block_root, envelope))
            .collect();
        let count = blocks.len();
        for (position, block) in blocks.into_iter().enumerate() {
            let root = block.block_root();
            let block = Arc::new(block);
            let payload = self.execution.verdict(&self.chain, &block).await;
            match self
                .chain
                .run(move |chain| chain.submit_block(block, payload))
                .await
            {
                Ok(Ok(_)) | Err(_) => {}
                // A first block without a parent means the node sits on another branch.
                Ok(Err(ChainError::ForkChoice(ForkChoiceError::UnknownParent { .. })))
                    if position == 0 =>
                {
                    return Verdict::UnknownParent;
                }
                Ok(Err(error)) => return Verdict::Invalid(error.to_string()),
            }
            if let Some(envelope) = envelopes.remove(&root) {
                let envelope = Arc::new(envelope);
                let payload = self.execution.judge_envelope(&self.chain, &envelope).await;
                if let Ok(Err(error)) = self
                    .chain
                    .run(move |chain| chain.submit_envelope(envelope, payload))
                    .await
                {
                    return Verdict::Invalid(error.to_string());
                }
            }
        }
        if count > 0 {
            info!(blocks = count, "synced batch");
        }
        Verdict::Done
    }
}
