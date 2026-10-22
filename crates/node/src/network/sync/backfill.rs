//! Backfill: fetching the blocks below a checkpoint anchor, newest first, down to the target.

use std::{collections::HashMap, sync::Arc};

use axiom_p2p::{
    PeerId,
    eth::reqresp::{ResponseChunk, Status},
    swarm::{NetworkHandle, RequestId},
};
use axiom_types::{ChainConfig, ColumnIndex, Preset, Slot};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task,
};
use tracing::{debug, info, warn};

use super::{BATCH_SLOTS, Batch, Fetch, MAX_STRIKES, Received};
use crate::{
    ChainError, ChainHandle, HistorySegment, HistoryStart, Reconstruction, SegmentContext,
    SegmentError, network::ForkDigests,
};

/// Slots of past states one rebuild step replays on the chain thread.
///
/// A step blocks the chain thread, so it stays short.
/// Replay without signatures runs a few mainnet blocks per hundred milliseconds.
const RECONSTRUCTION_STEP_SLOTS: u64 = 8;

/// What processing a backfill batch led to.
#[derive(Debug)]
enum Verdict {
    /// The segment is stored; the history now starts here.
    Stored(HistoryStart),
    /// The range held no block; the next range lies below it.
    Empty(Slot),
    /// The segment does not link to the stored history; fetch again from the stored start.
    Unlinked(String),
    /// The peer served invalid data.
    Invalid(String),
}

/// A processed backfill batch, reported back to the network loop.
#[derive(Debug)]
pub(crate) struct BackfillOutcome {
    /// The peer that served it.
    peer: PeerId,
    /// What happened.
    verdict: Verdict,
}

/// Backfill: the history below the anchor, one batch at a time, newest first.
///
/// # Overview
///
/// A checkpoint sync starts from a trusted block and stores nothing before it.
/// Backfill fetches that past, so the node can serve it and, as an archive, rebuild it.
///
/// 1. Ask a peer for the range just below the stored history, within one fork.
/// 2. Check the blob data's proofs, then the segment against the stored start.
/// 3. Store the segment, which moves the history start down.
/// 4. Stop at the target: genesis for an archive, the serving window otherwise.
///
/// The history start is stored with each segment, so a restart resumes where it stopped.
/// An empty range moves only the in-memory cursor, so a restart fetches it again.
///
/// Once an archive's history reaches genesis, the snapshots below the anchor are rebuilt.
/// The rebuild runs in short steps on the chain thread, interleaved with its other work.
#[derive(Debug)]
pub(crate) struct BackfillSync<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The network, for requests.
    network: NetworkHandle,
    /// The fork schedule, which bounds batches and picks what they fetch.
    config: ChainConfig,
    /// The digest each item's context bytes must carry.
    forks: Arc<ForkDigests>,
    /// Latest status of every connected peer.
    peers: HashMap<PeerId, Status>,
    /// Failed batches per peer.
    strikes: HashMap<PeerId, u32>,
    /// The batch being fetched, if any.
    batch: Option<Batch<P>>,
    /// Whether a fetched batch is being processed.
    processing: bool,
    /// The slot below which the next range ends, when empty ranges moved it below the stored start.
    cursor: Option<Slot>,
    /// Whether the rebuild of past states was started.
    rebuilding: bool,
    /// Where processing tasks report.
    outcomes: UnboundedSender<BackfillOutcome>,
}

impl<P: Preset> BackfillSync<P> {
    /// A backfill with no peer yet, and the receiver its processing reports to.
    pub(crate) fn new(
        chain: ChainHandle<P>,
        network: NetworkHandle,
        config: ChainConfig,
        forks: Arc<ForkDigests>,
    ) -> (Self, UnboundedReceiver<BackfillOutcome>) {
        let (outcomes, receiver) = unbounded_channel();
        let backfill = Self {
            chain,
            network,
            config,
            forks,
            peers: HashMap::new(),
            strikes: HashMap::new(),
            batch: None,
            processing: false,
            cursor: None,
            rebuilding: false,
            outcomes,
        };
        (backfill, receiver)
    }

    /// Records a peer's status, and starts a batch if history is missing.
    pub(crate) async fn on_status(&mut self, peer: PeerId, status: Status) {
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
            warn!(peer = %batch.peer, %reason, "disconnecting peer for a bad backfill batch");
            self.drop_peer(&batch.peer).await;
            self.advance().await;
            return;
        }
        self.processing = true;
        let chain = self.chain.clone();
        let config = self.config.clone();
        let outcomes = self.outcomes.clone();
        task::spawn(async move {
            let outcome = BackfillWorker { chain, config }.process(batch).await;
            // A stopped network loop has nobody to tell.
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
    pub(crate) async fn on_outcome(&mut self, outcome: BackfillOutcome) {
        self.processing = false;
        match outcome.verdict {
            Verdict::Stored(start) => {
                debug!(slot = %start.slot, "backfilled history");
                self.cursor = None;
            }
            Verdict::Empty(below) => self.cursor = Some(below),
            // An earlier empty range may have hidden blocks; the stored start is the safe restart.
            Verdict::Unlinked(reason) => {
                debug!(peer = %outcome.peer, %reason, "backfill segment does not link");
                self.strike(&outcome.peer);
                self.cursor = None;
            }
            Verdict::Invalid(reason) => {
                warn!(peer = %outcome.peer, %reason, "disconnecting peer for a bad backfill batch");
                self.drop_peer(&outcome.peer).await;
                self.cursor = None;
            }
        }
        self.advance().await;
    }

    /// Starts the next batch if history is missing and a peer can serve it.
    async fn advance(&mut self) {
        if self.batch.is_some() || self.processing {
            return;
        }
        let Ok(Ok((start, target, current, sampled))) = self
            .chain
            .run(|chain| {
                let start = chain.database().history_start()?;
                let target = chain.backfill_target()?;
                let sampled: Vec<ColumnIndex> = chain.custody().iter().copied().collect();
                Ok::<_, ChainError>((start, target, chain.store().current_slot(), sampled))
            })
            .await
        else {
            return;
        };
        let (Some(start), Some(target)) = (start, target) else {
            self.rebuild();
            return;
        };

        // The range ends below the stored start, or below the last empty range.
        let end = self.cursor.map_or(start.slot, |cursor| cursor.min(start.slot));
        if end <= target {
            return;
        }
        // A batch stays within one fork, so all of it decodes and checks under one fork.
        let last = end - 1;
        let fork_start = self
            .config
            .fork_epoch(self.config.fork_at(last.epoch::<P>()))
            .start_slot::<P>();
        let first = Slot(end.0.saturating_sub(BATCH_SLOTS))
            .max(target)
            .max(fork_start);
        let count = end - first;

        // The usable peer with the oldest history serves the batch.
        let strikes = &self.strikes;
        let Some(peer) = self
            .peers
            .iter()
            .filter(|(peer, status)| {
                strikes.get(*peer).copied().unwrap_or(0) < MAX_STRIKES
                    && status.earliest_available_slot <= first
                    && status.head_slot >= last
            })
            .min_by_key(|(_, status)| status.earliest_available_slot)
            .map(|(peer, _)| peer.clone())
        else {
            return;
        };
        let fetches = Fetch::for_range::<P>(&self.config, first, current, &sampled);
        match Batch::send(&self.network, peer, (first, count), &fetches, &sampled).await {
            Ok(batch) => self.batch = Some(batch),
            Err(error) => warn!(%error, "could not request a backfill batch"),
        }
    }

    /// Starts rebuilding past states in the background, once.
    fn rebuild(&mut self) {
        if self.rebuilding {
            return;
        }
        self.rebuilding = true;
        let chain = self.chain.clone();
        task::spawn(async move {
            loop {
                let step = chain
                    .run(|chain| chain.reconstruct_history(RECONSTRUCTION_STEP_SLOTS))
                    .await;
                match step {
                    Ok(Ok(Reconstruction::Progressed(_))) => {}
                    Ok(Ok(Reconstruction::Done)) => {
                        info!("past states rebuilt");
                        break;
                    }
                    Ok(Ok(Reconstruction::Waiting)) | Err(_) => break,
                    Ok(Err(error)) => {
                        warn!(%error, "rebuilding past states failed");
                        break;
                    }
                }
            }
        });
    }

    /// Counts a failed batch against a peer.
    fn strike(&mut self, peer: &PeerId) {
        *self.strikes.entry(peer.clone()).or_default() += 1;
    }

    /// Stops using a peer and disconnects it.
    async fn drop_peer(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
        self.strikes.insert(peer.clone(), MAX_STRIKES);
        // A disconnect only fails when the network is gone, which ends backfill anyway.
        let _stopped = self.network.disconnect(peer.clone()).await;
    }
}

/// Verifies and stores one backfill batch, away from the network loop.
#[derive(Debug)]
struct BackfillWorker<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The fork schedule, for the signature domains and the blob checks.
    config: ChainConfig,
}

impl<P: Preset> BackfillWorker<P> {
    /// Checks the blob data, then the segment, then stores it.
    async fn process(self, batch: Batch<P>) -> BackfillOutcome {
        let Batch {
            peer,
            start,
            received,
            ..
        } = batch;
        let verdict = self.verdict(start, received).await;
        BackfillOutcome { peer, verdict }
    }

    /// What the batch amounts to.
    async fn verdict(&self, first: Slot, received: Received<P>) -> Verdict {
        // KZG and signature checks are CPU-bound, so they run on the blocking pool.
        let config = self.config.clone();
        let checked =
            task::spawn_blocking(move || received.verify(&config).map(|()| received)).await;
        let received = match checked {
            Ok(Ok(received)) => received,
            Ok(Err(reason)) => return Verdict::Invalid(reason),
            Err(_) => return Verdict::Empty(first),
        };
        let Received {
            blocks,
            blobs,
            columns,
            envelopes,
        } = received;
        let segment = HistorySegment::new(blocks, blobs, columns, envelopes);
        if segment.is_empty() {
            return Verdict::Empty(first);
        }

        let proposers = segment.proposers();
        let Ok(Ok((keys, genesis_validators_root, start, current, sampled))) = self
            .chain
            .run(move |chain| {
                let start = chain
                    .database()
                    .history_start()?
                    .ok_or(ChainError::Missing("history start"))?;
                let sampled: Vec<ColumnIndex> = chain.custody().iter().copied().collect();
                Ok::<_, ChainError>((
                    chain.proposer_keys(proposers),
                    chain.genesis_validators_root(),
                    start,
                    chain.store().current_slot(),
                    sampled,
                ))
            })
            .await
        else {
            return Verdict::Empty(first);
        };
        let config = self.config.clone();
        let verified = task::spawn_blocking(move || {
            let context = SegmentContext {
                config: &config,
                genesis_validators_root,
                keys: &keys,
                sampled: &sampled,
                retained: Fetch::is_retained::<P>(&config, first, current),
            };
            segment.verify(start, &context)
        })
        .await;
        let verified = match verified {
            Ok(Ok(verified)) => verified,
            Ok(Err(
                error @ (SegmentError::BrokenLink { .. }
                | SegmentError::NotBeforeStart { .. }
                | SegmentError::Unordered { .. }),
            )) => return Verdict::Unlinked(error.to_string()),
            Ok(Err(error)) => return Verdict::Invalid(error.to_string()),
            Err(_) => return Verdict::Empty(first),
        };
        let count = verified.len();
        match self
            .chain
            .run(move |chain| chain.import_history(&verified))
            .await
        {
            Ok(Ok(start)) => {
                info!(blocks = count, slot = %start.slot, "backfilled batch");
                Verdict::Stored(start)
            }
            // A segment that buries another block than the trusted checkpoint is another chain.
            Ok(Err(error @ ChainError::WeakSubjectivity(_))) => Verdict::Invalid(error.to_string()),
            Ok(Err(error)) => Verdict::Unlinked(error.to_string()),
            Err(_) => Verdict::Empty(first),
        }
    }
}
