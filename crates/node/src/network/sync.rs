//! Catching up: fetching blocks and their columns from peers that are ahead.

use std::{collections::HashMap, sync::Arc};

use axiom_das::ColumnSidecar;
use axiom_fork_choice::ForkChoiceError;
use axiom_kzg::Kzg;
use axiom_p2p::{
    PeerId,
    eth::reqresp::{Protocol, ResponseChunk, ResponseCode, Status},
    swarm::{NetworkError, NetworkHandle, RequestId},
};
use axiom_ssz::{List, Ssz};
use axiom_types::{ChainConfig, ColumnIndex, DataColumnSidecar, Preset, SignedBeaconBlock, Slot};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task,
};
use tracing::{debug, info, warn};

use super::requests::{BlocksByRangeRequest, ColumnsByRangeRequest};
use crate::{ChainError, ChainHandle, ExecutionLayer};

/// Slots fetched per batch.
///
/// One epoch on mainnet: small enough to retry cheaply, large enough to amortize the round trip.
const BATCH_SLOTS: u64 = 32;

/// Failed batches after which a peer is no longer asked.
///
/// A peer that times out or answers with errors this often is useless for sync, if not hostile.
const MAX_STRIKES: u32 = 3;

/// One range being fetched from one peer.
#[derive(Debug)]
struct Batch<P: Preset> {
    /// The peer serving it.
    peer: PeerId,
    /// First slot of the range.
    start: Slot,
    /// Slots in the range.
    count: u64,
    /// The blocks request.
    blocks_request: RequestId,
    /// The columns request, when the node samples any column.
    columns_request: Option<RequestId>,
    /// Requests still streaming.
    open: usize,
    /// Whether the peer answered with an error.
    failed: bool,
    /// Blocks received so far.
    blocks: Vec<SignedBeaconBlock<P>>,
    /// Columns received so far.
    columns: Vec<DataColumnSidecar<P>>,
}

/// What processing a batch led to.
#[derive(Debug)]
enum Verdict {
    /// Every block imported or waits for columns; the range is done.
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
/// ```text
///     status ──> valid fork digest, head not in the future? else disconnect
///                                   │
///     cursor ──> blocks by range [cursor, cursor + 32) + sampled columns by range
///                                   │
///     background task: columns (structure, inclusion, KZG) then blocks (engine, import)
///                                   │
///     done: cursor moves past the range, empty or not
///     unknown parent: the head is on a dead fork; rewind the cursor to finality
///     invalid data: disconnect the peer
/// ```
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
    ) -> (Self, UnboundedReceiver<BatchOutcome>) {
        let (outcomes, receiver) = unbounded_channel();
        let sync = Self {
            chain,
            execution,
            network,
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
        let Ok((digest, current)) = self
            .chain
            .run(|chain| {
                let current = chain.store().current_slot();
                (chain.fork_digest(current.epoch::<P>()), current)
            })
            .await
        else {
            return;
        };
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
        self.batch.as_ref().is_some_and(|batch| {
            batch.blocks_request == request || batch.columns_request == Some(request)
        })
    }

    /// Takes one response chunk of the batch.
    pub(crate) fn on_chunk(&mut self, request: RequestId, chunk: &ResponseChunk) {
        let Some(batch) = &mut self.batch else {
            return;
        };
        if chunk.code != ResponseCode::Success {
            debug!(peer = %batch.peer, code = ?chunk.code, "batch request answered with an error");
            batch.failed = true;
            return;
        }
        // An undecodable chunk is dropped here; the batch then fails its checks and the peer goes.
        if request == batch.blocks_request {
            if let Ok(block) = SignedBeaconBlock::decode(&chunk.payload) {
                batch.blocks.push(block);
            }
        } else if let Ok(column) = DataColumnSidecar::decode(&chunk.payload) {
            batch.columns.push(column);
        }
    }

    /// Marks one of the batch's requests finished, starting processing once both are.
    pub(crate) async fn on_end(&mut self, request: RequestId) {
        let Some(batch) = &mut self.batch else {
            return;
        };
        if batch.blocks_request == request || batch.columns_request == Some(request) {
            batch.open -= 1;
        }
        if batch.open > 0 {
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
        let Ok((head, sampled)) = self
            .chain
            .run(|chain| {
                (
                    chain.head().slot,
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
        let count = BATCH_SLOTS.min(status.head_slot.0 - start.0 + 1);
        if let Err(error) = self.request(peer, start, count, sampled).await {
            warn!(%error, "could not request a batch");
        }
    }

    /// Sends the requests of a batch.
    async fn request(
        &mut self,
        peer: PeerId,
        start: Slot,
        count: u64,
        sampled: Vec<ColumnIndex>,
    ) -> Result<(), NetworkError> {
        let blocks = BlocksByRangeRequest {
            start_slot: start,
            count,
            step: 1,
        };
        let blocks_request = self
            .network
            .send_request(
                peer.clone(),
                Protocol::BeaconBlocksByRangeV2,
                blocks.encode(),
            )
            .await?;
        let columns_request = if sampled.is_empty() {
            None
        } else {
            let columns = ColumnsByRangeRequest::<P> {
                start_slot: start,
                count,
                // Sampled columns never exceed the column count, so the list always fits.
                columns: List::try_from(sampled).unwrap_or_default(),
            };
            Some(
                self.network
                    .send_request(
                        peer.clone(),
                        Protocol::DataColumnSidecarsByRangeV1,
                        columns.encode(),
                    )
                    .await?,
            )
        };
        debug!(%peer, start = %start, count, "requested batch");
        self.batch = Some(Batch {
            peer,
            start,
            count,
            blocks_request,
            columns_request,
            open: 1 + usize::from(columns_request.is_some()),
            failed: false,
            blocks: Vec::new(),
            columns: Vec::new(),
        });
        Ok(())
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
    /// Columns first, so each block is available the moment it is submitted, then blocks in order.
    async fn process(self, batch: Batch<P>) -> BatchOutcome {
        let Batch {
            peer,
            start,
            count,
            blocks,
            columns,
            ..
        } = batch;
        let end = Slot(start.0 + count);
        let verdict = self.verdict(blocks, columns).await;
        BatchOutcome { peer, end, verdict }
    }

    /// Checks and imports the batch's contents.
    async fn verdict(
        &self,
        blocks: Vec<SignedBeaconBlock<P>>,
        columns: Vec<DataColumnSidecar<P>>,
    ) -> Verdict {
        let Ok(config) = self.chain.run(|chain| chain.config().clone()).await else {
            return Verdict::Done;
        };

        // KZG checks are CPU-bound, so they run on the blocking pool.
        let checked = task::spawn_blocking(move || Self::check_columns(&config, columns)).await;
        let columns = match checked {
            Ok(Ok(columns)) => columns,
            Ok(Err(reason)) => return Verdict::Invalid(reason.to_owned()),
            Err(_) => return Verdict::Done,
        };
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

        let count = blocks.len();
        for (position, block) in blocks.into_iter().enumerate() {
            let block = Arc::new(block);
            let payload = self.execution.verdict(&block.message).await;
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
        }
        if count > 0 {
            info!(blocks = count, "synced batch");
        }
        Verdict::Done
    }

    /// Every column must be well formed, included in its block, and open its commitments.
    fn check_columns(
        config: &ChainConfig,
        columns: Vec<DataColumnSidecar<P>>,
    ) -> Result<Vec<DataColumnSidecar<P>>, &'static str> {
        for column in &columns {
            let sidecar = ColumnSidecar(column);
            let valid = sidecar.verify_structure(config).is_ok()
                && sidecar.verify_inclusion_proof().is_ok()
                && sidecar.verify_kzg_proofs(Kzg::mainnet()).is_ok();
            if !valid {
                return Err("invalid column in batch");
            }
        }
        Ok(columns)
    }
}
