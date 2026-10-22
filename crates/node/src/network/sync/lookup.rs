//! Lookups: fetching by root the blocks gossip named that the chain does not know.

use std::{collections::HashMap, mem, sync::Arc};

use axiom_p2p::{
    PeerId,
    eth::reqresp::ResponseChunk,
    swarm::{NetworkHandle, RequestId},
};
use axiom_ssz::{List, Ssz};
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    BlobData, BlobIndex, ChainConfig, ColumnIndex, Preset, Root, Slot, combined,
    deneb::BlobIdentifier, fulu::DataColumnsByRootIdentifier,
};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task,
};
use tracing::{debug, info, warn};

use super::{Batch, BatchWorker, Fetch, Verdict};
use crate::{
    ChainHandle, EventSender, ExecutionLayer,
    network::{
        ForkDigests,
        gossip::GossipSinks,
        requests::{
            BlobsByRootRequest, BlocksByRootRequest, ColumnsByRootRequest, EnvelopesByRootRequest,
        },
    },
};

/// Deepest chain of unknown ancestors a lookup follows, in blocks.
///
/// A peer's chain that far ahead of the node is a sync target, not a missed block or two.
/// Past this depth the lookup stops, and range sync takes over from the peers' statuses.
/// It matches the slot tolerance within which a node counts as synced with its peers.
const PARENT_DEPTH_TOLERANCE: usize = 32;

/// Most lookups held at once.
///
/// Lookups hold unverified blocks of up to 10 MB each from untrusted peers.
/// Two hundred of them bound that memory, while leaving room for a few full-depth chains.
const MAX_LOOKUPS: usize = 200;

/// Requests for one root before the lookup gives up on it.
const MAX_ATTEMPTS: u32 = 4;

/// How long a failed lookup's roots are ignored, in milliseconds.
///
/// Gossip keeps naming a root the node could not fetch; retrying at once only repeats the failure.
const IGNORED_ROOT_EXPIRY_MS: u64 = 60_000;

/// A block a gossip message needed, which the chain does not know.
#[derive(Clone, Debug)]
pub(crate) enum MissingBlock<P: Preset> {
    /// A gossip block whose parent is unknown; the block itself is kept.
    Parent(Arc<combined::SignedBeaconBlock<P>>),
    /// A root a vote named.
    Root(Root),
}

/// What reaches the lookups besides network responses.
#[derive(Debug)]
pub(crate) enum LookupEvent<P: Preset> {
    /// A peer's gossip needs a block the chain does not know.
    Missing {
        /// The peer that sent the gossip, and so claims to know the block.
        peer: PeerId,
        /// The missing block, or the block that needs it.
        missing: MissingBlock<P>,
    },
    /// A resolved chain was verified and imported, or refused.
    Processed {
        /// Root of the lookup's newest block.
        tip: Root,
        /// The peer whose data was processed.
        peer: PeerId,
        /// What processing led to.
        verdict: Verdict,
    },
}

/// Where a lookup stands.
#[derive(Debug)]
enum Stage<P: Preset> {
    /// Fetching the oldest unknown ancestor by root.
    Ancestor(Batch<P>),
    /// Waiting for another lookup that holds the oldest unknown ancestor.
    Parked,
    /// Fetching the blob data and payloads of the chain, now that it links to the node's.
    Data(Batch<P>),
    /// Verifying and importing, off the network loop.
    Processing,
}

/// One chain of unknown blocks, from the block gossip named back to a known ancestor.
#[derive(Debug)]
struct Lookup<P: Preset> {
    /// Peers that claimed the newest block; requests rotate among them.
    peers: Vec<PeerId>,
    /// The blocks fetched so far, newest first, each the parent of the one before.
    blocks: Vec<Arc<combined::SignedBeaconBlock<P>>>,
    /// The root to fetch next: the parent of the oldest block, or the newest root itself.
    wanted: Root,
    /// Failed requests for the wanted root.
    attempts: u32,
    /// What the lookup is doing.
    stage: Stage<P>,
}

impl<P: Preset> Lookup<P> {
    /// The peer the next request goes to, rotating as attempts fail.
    fn peer(&self) -> Option<PeerId> {
        let count = self.peers.len();
        (count > 0).then(|| self.peers[self.attempts as usize % count].clone())
    }

    /// The batch in flight, if any.
    const fn batch(&self) -> Option<&Batch<P>> {
        match &self.stage {
            Stage::Ancestor(batch) | Stage::Data(batch) => Some(batch),
            Stage::Parked | Stage::Processing => None,
        }
    }

    /// Whether the lookup holds a block, fetched or awaited.
    fn holds(&self, root: Root) -> bool {
        self.wanted == root || self.blocks.iter().any(|block| block.block_root() == root)
    }
}

/// What the chain says about a root a lookup may chase.
#[derive(Clone, Copy, Debug)]
struct ChainFacts {
    /// Whether the chain already holds the root.
    known: bool,
    /// Whether the node's head is within the tolerance of the clock.
    synced: bool,
}

/// Block lookups: unknown blocks fetched by root, and their parents, until they link up.
///
/// # Overview
///
/// Gossip names blocks the node may lack: a block's parent, or the block a vote is for.
/// The p2p spec lets a client fetch such a block and handle the message once it arrives.
///
/// 1. Ask a peer that sent the gossip for the unknown root.
/// 2. While the fetched block's parent is unknown too, ask for that parent, one level deeper.
/// 3. Once the chain links to a known block, fetch its blobs, columns, or payloads by root.
/// 4. Verify and import the chain, oldest block first.
///
/// A chain deeper than the sync tolerance is left to range sync.
/// A peer that serves a block other than the one asked for, or invalid data, is disconnected.
/// A root no peer could serve is ignored for a minute.
///
/// See the blocks, blobs, columns, and envelopes by root methods of the p2p specs.
#[derive(Debug)]
pub(crate) struct BlockLookups<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for judging payloads.
    execution: Arc<ExecutionLayer>,
    /// The network, for requests.
    network: NetworkHandle,
    /// The fork schedule, which decides what data each block needs.
    config: ChainConfig,
    /// The digest each item's context bytes must carry.
    forks: Arc<ForkDigests>,
    /// Lookups by the root of their newest block.
    lookups: HashMap<Root, Lookup<P>>,
    /// Roots of failed lookups, with when they may be chased again.
    ignored: HashMap<Root, u64>,
    /// Peers whose chains were too deep, for range sync to ask their status.
    handoffs: Vec<PeerId>,
    /// Peers dropped for bad answers, for peer management to score.
    dropped: Vec<PeerId>,
    /// Whether a lookup ended, so the lookups parked behind it should move on.
    ended: bool,
    /// Lookup counts.
    metrics: NodeMetrics,
    /// Where processing tasks and gossip report.
    events: UnboundedSender<LookupEvent<P>>,
}

impl<P: Preset> BlockLookups<P> {
    /// Lookups with nothing to fetch yet, and the receiver gossip and processing report to.
    pub(crate) fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        network: NetworkHandle,
        config: ChainConfig,
        forks: Arc<ForkDigests>,
        metrics: NodeMetrics,
    ) -> (Self, UnboundedReceiver<LookupEvent<P>>) {
        let (events, receiver) = unbounded_channel();
        let lookups = Self {
            chain,
            execution,
            network,
            config,
            forks,
            lookups: HashMap::new(),
            ignored: HashMap::new(),
            handoffs: Vec::new(),
            dropped: Vec::new(),
            ended: false,
            metrics,
            events,
        };
        (lookups, receiver)
    }

    /// Where gossip goes besides the chain: event stream clients, and these lookups.
    pub(crate) fn sinks(&self, events: EventSender) -> GossipSinks<P> {
        GossipSinks {
            events,
            lookups: self.events.clone(),
        }
    }

    /// Takes the peers dropped for bad answers since the last call.
    pub(crate) fn take_dropped(&mut self) -> Vec<PeerId> {
        mem::take(&mut self.dropped)
    }

    /// Takes the peers whose chains are for range sync to follow.
    pub(crate) fn take_handoffs(&mut self) -> Vec<PeerId> {
        mem::take(&mut self.handoffs)
    }

    /// Handles a missing block or a processed chain.
    pub(crate) async fn on_event(&mut self, event: LookupEvent<P>, now_ms: u64) {
        match event {
            LookupEvent::Missing { peer, missing } => self.on_missing(peer, missing, now_ms).await,
            LookupEvent::Processed { tip, peer, verdict } => {
                self.on_processed(tip, peer, verdict, now_ms).await;
            }
        }
        self.wake_parked(now_ms).await;
    }

    /// Whether a request belongs to a lookup.
    pub(crate) fn owns(&self, request: RequestId) -> bool {
        self.lookups
            .values()
            .any(|lookup| lookup.batch().is_some_and(|batch| batch.owns(request)))
    }

    /// Takes one response chunk of a lookup's request.
    pub(crate) fn on_chunk(&mut self, request: RequestId, chunk: &ResponseChunk) {
        let batch = self
            .lookups
            .values_mut()
            .find_map(|lookup| match &mut lookup.stage {
                Stage::Ancestor(batch) | Stage::Data(batch) if batch.owns(request) => Some(batch),
                _ => None,
            });
        if let Some(batch) = batch {
            batch.on_chunk(&self.config, &self.forks, request, chunk);
        }
    }

    /// Marks one request finished, moving its lookup on once all of its batch's are.
    pub(crate) async fn on_end(&mut self, request: RequestId, now_ms: u64) {
        let Some(tip) = self.tip_of(request) else {
            return;
        };
        let Some(lookup) = self.lookups.get_mut(&tip) else {
            return;
        };
        let finished = match &mut lookup.stage {
            Stage::Ancestor(batch) | Stage::Data(batch) => batch.on_end(request),
            Stage::Parked | Stage::Processing => false,
        };
        if !finished {
            return;
        }
        // Invariant: the request was owned by this lookup's batch, so it is in one of these stages.
        match mem::replace(&mut lookup.stage, Stage::Parked) {
            Stage::Ancestor(batch) => self.on_ancestor(tip, batch, now_ms).await,
            Stage::Data(batch) => self.on_data(tip, batch, now_ms).await,
            stage @ (Stage::Parked | Stage::Processing) => lookup.stage = stage,
        }
        self.wake_parked(now_ms).await;
    }

    /// Retries a lookup whose request failed, with the next peer.
    pub(crate) async fn on_failure(&mut self, request: RequestId, now_ms: u64) {
        let Some(tip) = self.tip_of(request) else {
            return;
        };
        if let Some(lookup) = self.lookups.get_mut(&tip) {
            lookup.attempts += 1;
            lookup.stage = Stage::Parked;
        }
        self.advance(tip, now_ms).await;
        self.wake_parked(now_ms).await;
    }

    /// Forgets a peer, retrying the lookups it was serving with the others.
    pub(crate) async fn on_disconnect(&mut self, peer: &PeerId, now_ms: u64) {
        let mut orphaned = Vec::new();
        for (tip, lookup) in &mut self.lookups {
            lookup.peers.retain(|known| known != peer);
            if lookup.batch().is_some_and(|batch| batch.peer == *peer) {
                lookup.stage = Stage::Parked;
                orphaned.push(*tip);
            }
        }
        for tip in orphaned {
            self.advance(tip, now_ms).await;
        }
        self.wake_parked(now_ms).await;
    }

    /// Starts or joins the lookup of a missing block.
    async fn on_missing(&mut self, peer: PeerId, missing: MissingBlock<P>, now_ms: u64) {
        let (tip, blocks, wanted) = match missing {
            MissingBlock::Parent(block) => {
                let parent = block.parent_root();
                (block.block_root(), vec![block], parent)
            }
            MissingBlock::Root(root) => (root, Vec::new(), root),
        };
        self.ignored.retain(|_, until| *until > now_ms);
        if self.ignored.contains_key(&tip) || self.ignored.contains_key(&wanted) {
            return;
        }
        // A lookup already holding the block gains a peer that claims it.
        if let Some(lookup) = self.lookups.values_mut().find(|lookup| lookup.holds(tip)) {
            if !lookup.peers.contains(&peer) {
                lookup.peers.push(peer);
            }
            return;
        }
        if self.lookups.len() >= MAX_LOOKUPS {
            debug!(%tip, "too many lookups; dropping the missing block");
            return;
        }
        let Some(facts) = self.facts(tip).await else {
            return;
        };
        // Far behind, the gap is range sync's; a known block needs nothing.
        if facts.known || !facts.synced {
            return;
        }
        debug!(%tip, %wanted, %peer, "looking up a missing block");
        self.metrics.sync_lookups_created.inc();
        self.lookups.insert(
            tip,
            Lookup {
                peers: vec![peer],
                blocks,
                wanted,
                attempts: 0,
                stage: Stage::Parked,
            },
        );
        self.advance(tip, now_ms).await;
    }

    /// Takes the answer to an ancestor request: the wanted block, or nothing.
    async fn on_ancestor(&mut self, tip: Root, batch: Batch<P>, now_ms: u64) {
        let Some(wanted) = self.lookups.get(&tip).map(|lookup| lookup.wanted) else {
            return;
        };
        let mut blocks = batch.received.blocks;
        let served = match (batch.failed, batch.fault, blocks.pop()) {
            // A peer may not hold the block; another may.
            (true, _, _) | (false, None, None) => None,
            (false, Some(reason), _) => {
                self.penalize(&batch.peer, &reason).await;
                None
            }
            (false, None, Some(block)) if block.block_root() == wanted && blocks.is_empty() => {
                Some(block)
            }
            (false, None, Some(_)) => {
                self.penalize(&batch.peer, &format!("served another block than {wanted}"))
                    .await;
                None
            }
        };
        let Some(lookup) = self.lookups.get_mut(&tip) else {
            return;
        };
        match served {
            Some(block) => {
                lookup.wanted = block.parent_root();
                lookup.attempts = 0;
                lookup.blocks.push(Arc::new(block));
            }
            None => lookup.attempts += 1,
        }
        self.advance(tip, now_ms).await;
    }

    /// Takes the chain's data, then verifies and imports the chain away from the network loop.
    async fn on_data(&mut self, tip: Root, batch: Batch<P>, now_ms: u64) {
        if batch.failed {
            if let Some(lookup) = self.lookups.get_mut(&tip) {
                lookup.attempts += 1;
            }
            return self.advance(tip, now_ms).await;
        }
        if let Some(reason) = &batch.fault {
            self.penalize(&batch.peer, reason).await;
            if let Some(lookup) = self.lookups.get_mut(&tip) {
                lookup.attempts += 1;
            }
            return self.advance(tip, now_ms).await;
        }
        self.process(tip, batch);
    }

    /// Verifies and imports a lookup's chain with the data its batch fetched, off the network loop.
    fn process(&mut self, tip: Root, batch: Batch<P>) {
        let Some(lookup) = self.lookups.get_mut(&tip) else {
            return;
        };
        lookup.stage = Stage::Processing;
        let mut received = batch.received;
        // Oldest first, so each block's parent is imported before it.
        received.blocks = lookup
            .blocks
            .iter()
            .rev()
            .map(|block| (**block).clone())
            .collect();
        let worker = BatchWorker {
            chain: self.chain.clone(),
            execution: Arc::clone(&self.execution),
        };
        let events = self.events.clone();
        let peer = batch.peer;
        task::spawn(async move {
            let verdict = worker.verdict(received).await;
            // A stopped network loop has nobody to tell.
            let _stopped = events.send(LookupEvent::Processed { tip, peer, verdict });
        });
    }

    /// Ends a processed lookup, and wakes the lookups that waited for its blocks.
    async fn on_processed(&mut self, tip: Root, peer: PeerId, verdict: Verdict, now_ms: u64) {
        let Some(lookup) = self.lookups.remove(&tip) else {
            return;
        };
        self.ended = true;
        match verdict {
            // A block may still wait for blob data the peer did not have, so its import is checked.
            Verdict::Done if self.facts(tip).await.is_some_and(|facts| facts.known) => {
                info!(blocks = lookup.blocks.len(), %tip, "imported looked up blocks");
                self.metrics.sync_lookups_completed.inc();
            }
            Verdict::Done => self.drop_lookup(&lookup, "data unavailable", now_ms),
            Verdict::UnknownParent => self.drop_lookup(&lookup, "unknown parent", now_ms),
            Verdict::Invalid(reason) => {
                self.penalize(&peer, &reason).await;
                self.drop_lookup(&lookup, "invalid", now_ms);
            }
        }
    }

    /// Moves on the lookups that waited for another, once some lookup has ended.
    ///
    /// The ended lookup may have imported the block they wait for, or given up on it.
    /// Either way they move: to their data, or to fetching the block themselves.
    async fn wake_parked(&mut self, now_ms: u64) {
        if !mem::take(&mut self.ended) {
            return;
        }
        let parked: Vec<Root> = self
            .lookups
            .iter()
            .filter(|(_, lookup)| matches!(lookup.stage, Stage::Parked))
            .map(|(tip, _)| *tip)
            .collect();
        for tip in parked {
            self.advance(tip, now_ms).await;
        }
    }

    /// Moves a lookup on from where it stands.
    ///
    /// 1. Too many failures or no peer left: drop it.
    /// 2. Its oldest block links to the chain: fetch the chain's data.
    /// 3. Too deep: drop it, and leave the chain to range sync.
    /// 4. Another lookup holds the wanted block: wait for it.
    /// 5. Otherwise: ask for the wanted block.
    async fn advance(&mut self, tip: Root, now_ms: u64) {
        let Some(lookup) = self.lookups.get(&tip) else {
            return;
        };
        let wanted = lookup.wanted;
        let depth = lookup.blocks.len();
        let Some(peer) = lookup.peer().filter(|_| lookup.attempts < MAX_ATTEMPTS) else {
            return self.give_up(tip, "no peer served it", now_ms);
        };
        let Some(facts) = self.facts(wanted).await else {
            return;
        };
        if facts.known && depth > 0 {
            return self.fetch_data(tip, peer, now_ms).await;
        }
        if facts.known {
            // The root itself arrived meanwhile, through gossip or another lookup.
            self.lookups.remove(&tip);
            self.ended = true;
            return;
        }
        if depth > PARENT_DEPTH_TOLERANCE {
            let peers = self
                .lookups
                .get(&tip)
                .map(|lookup| lookup.peers.clone())
                .unwrap_or_default();
            debug!(%tip, depth, "chain too deep for a lookup; leaving it to range sync");
            self.handoffs.extend(peers);
            return self.give_up(tip, "too deep", now_ms);
        }
        let held_elsewhere = self
            .lookups
            .iter()
            .any(|(other, lookup)| *other != tip && lookup.holds(wanted));
        if held_elsewhere {
            if let Some(lookup) = self.lookups.get_mut(&tip) {
                lookup.stage = Stage::Parked;
            }
            return;
        }
        let body = BlocksByRootRequest::try_from(vec![wanted])
            .map(|request| request.encode())
            .unwrap_or_default();
        match Batch::by_root(&self.network, peer, vec![(Fetch::Blocks, body)]).await {
            Ok(batch) => {
                if let Some(lookup) = self.lookups.get_mut(&tip) {
                    lookup.stage = Stage::Ancestor(batch);
                }
            }
            Err(error) => {
                warn!(%error, "could not request a block by root");
                self.give_up(tip, "network", now_ms);
            }
        }
    }

    /// Asks a peer for the blob data and payloads of a lookup's chain, or processes it at once.
    async fn fetch_data(&mut self, tip: Root, peer: PeerId, now_ms: u64) {
        let Ok((current, sampled)) = self
            .chain
            .run(|chain| {
                let sampled: Vec<ColumnIndex> = chain.custody().iter().copied().collect();
                (chain.store().current_slot(), sampled)
            })
            .await
        else {
            return;
        };
        let Some(lookup) = self.lookups.get(&tip) else {
            return;
        };
        let bodies = DataRequests::of(&self.config, &lookup.blocks, current, &sampled).bodies();
        match Batch::by_root(&self.network, peer, bodies).await {
            Ok(batch) if batch.open == 0 => self.process(tip, batch),
            Ok(batch) => {
                if let Some(lookup) = self.lookups.get_mut(&tip) {
                    lookup.stage = Stage::Data(batch);
                }
            }
            Err(error) => {
                warn!(%error, "could not request blob data by root");
                self.give_up(tip, "network", now_ms);
            }
        }
    }

    /// Drops a lookup that cannot finish.
    fn give_up(&mut self, tip: Root, reason: &'static str, now_ms: u64) {
        if let Some(lookup) = self.lookups.remove(&tip) {
            self.ended = true;
            self.drop_lookup(&lookup, reason, now_ms);
        }
    }

    /// Ignores a dropped lookup's roots for a while, and counts the drop.
    fn drop_lookup(&mut self, lookup: &Lookup<P>, reason: &'static str, now_ms: u64) {
        debug!(wanted = %lookup.wanted, reason, "lookup dropped");
        self.metrics
            .sync_lookups_dropped
            .with_label_values([reason])
            .inc();
        let until = now_ms.saturating_add(IGNORED_ROOT_EXPIRY_MS);
        self.ignored.insert(lookup.wanted, until);
        for block in &lookup.blocks {
            self.ignored.insert(block.block_root(), until);
        }
    }

    /// Disconnects a peer that served data no honest peer serves.
    async fn penalize(&mut self, peer: &PeerId, reason: &str) {
        warn!(%peer, %reason, "disconnecting peer for a bad lookup answer");
        for lookup in self.lookups.values_mut() {
            lookup.peers.retain(|known| known != peer);
        }
        self.dropped.push(peer.clone());
        // A disconnect only fails when the network is gone, which ends lookups anyway.
        let _stopped = self.network.disconnect(peer.clone()).await;
    }

    /// The lookup whose batch sent a request.
    fn tip_of(&self, request: RequestId) -> Option<Root> {
        self.lookups
            .iter()
            .find(|(_, lookup)| lookup.batch().is_some_and(|batch| batch.owns(request)))
            .map(|(tip, _)| *tip)
    }

    /// Whether the chain knows a root, and whether the node is close enough to sync by lookup.
    async fn facts(&self, root: Root) -> Option<ChainFacts> {
        self.chain
            .run(move |chain| {
                let behind = chain
                    .store()
                    .current_slot()
                    .0
                    .saturating_sub(chain.head().slot.0);
                ChainFacts {
                    known: chain.store().blocks().contains(&root),
                    synced: behind <= PARENT_DEPTH_TOLERANCE as u64,
                }
            })
            .await
            .ok()
    }
}

/// The by-root requests that fetch what a chain of blocks needs besides the blocks.
///
/// Each block's fork decides: blob sidecars, sampled columns, or a payload envelope.
/// Data past its retention window is not asked for, since peers may have dropped it.
#[derive(Debug, Default)]
struct DataRequests<P: Preset> {
    /// Blob sidecars, by block root and index.
    blobs: Vec<BlobIdentifier>,
    /// Sampled columns, by block root.
    columns: Vec<DataColumnsByRootIdentifier<P>>,
    /// Payload envelopes, by block root.
    envelopes: Vec<Root>,
}

impl<P: Preset> DataRequests<P> {
    /// What a chain of blocks needs, at the current slot, for the columns the node samples.
    fn of(
        config: &ChainConfig,
        blocks: &[Arc<combined::SignedBeaconBlock<P>>],
        current: Slot,
        sampled: &[ColumnIndex],
    ) -> Self {
        let mut requests = Self::default();
        let columns: List<ColumnIndex, P::NumberOfColumns> =
            List::try_from(sampled.to_vec()).unwrap_or_default();
        for block in blocks {
            let root = block.block_root();
            let slot = block.slot();
            let data = config.fork_at(slot.epoch::<P>()).blob_data();
            let retained = Fetch::is_retained::<P>(config, slot, current);
            let commitments = Self::commitments(block);
            match data {
                BlobData::BlobSidecars if retained => {
                    requests
                        .blobs
                        .extend((0..commitments as u64).map(|index| BlobIdentifier {
                            block_root: root,
                            index: BlobIndex(index),
                        }));
                }
                BlobData::BlockColumns | BlobData::PayloadColumns
                    if retained && commitments > 0 && !columns.is_empty() =>
                {
                    requests.columns.push(DataColumnsByRootIdentifier {
                        block_root: root,
                        columns: columns.clone(),
                    });
                }
                BlobData::None
                | BlobData::BlobSidecars
                | BlobData::BlockColumns
                | BlobData::PayloadColumns => {}
            }
            // Payloads come apart from their blocks from Gloas on, whatever their age.
            if data == BlobData::PayloadColumns {
                requests.envelopes.push(root);
            }
        }
        requests
    }

    /// Blobs a block commits to, in its body before Gloas, in its bid from then on.
    fn commitments(block: &combined::SignedBeaconBlock<P>) -> usize {
        match block {
            combined::SignedBeaconBlock::Gloas(signed) => signed
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments
                .len(),
            other => other.message().blob_kzg_commitments().len(),
        }
    }

    /// The encoded bodies of the requests, one per kind that asks for anything.
    ///
    /// A chain is at most the depth tolerance long, so every list fits its request's bound.
    fn bodies(self) -> Vec<(Fetch, Vec<u8>)> {
        let mut bodies = Vec::new();
        if !self.blobs.is_empty()
            && let Ok(request) = BlobsByRootRequest::try_from(self.blobs)
        {
            bodies.push((Fetch::Blobs, request.encode()));
        }
        if !self.columns.is_empty()
            && let Ok(request) = ColumnsByRootRequest::<P>::try_from(self.columns)
        {
            bodies.push((Fetch::Columns, request.encode()));
        }
        if !self.envelopes.is_empty()
            && let Ok(request) = EnvelopesByRootRequest::try_from(self.envelopes)
        {
            bodies.push((Fetch::Envelopes, request.encode()));
        }
        bodies
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Epoch, ForkName, KzgCommitment, Minimal, deneb, fulu, gloas, phase0};

    use super::*;

    /// A Deneb block at a slot committing to some blobs.
    fn deneb_block(slot: u64, blobs: usize) -> Arc<combined::SignedBeaconBlock<Minimal>> {
        let mut block = deneb::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        for _ in 0..blobs {
            block
                .message
                .body
                .blob_kzg_commitments
                .push(KzgCommitment::default())
                .unwrap();
        }
        Arc::new(combined::SignedBeaconBlock::Deneb(block))
    }

    /// A Fulu block at a slot committing to some blobs.
    fn fulu_block(slot: u64, blobs: usize) -> Arc<combined::SignedBeaconBlock<Minimal>> {
        let mut block = fulu::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        for _ in 0..blobs {
            block
                .message
                .body
                .blob_kzg_commitments
                .push(KzgCommitment::default())
                .unwrap();
        }
        Arc::new(combined::SignedBeaconBlock::Fulu(block))
    }

    /// A Gloas block at a slot whose bid commits to some blobs.
    fn gloas_block(slot: u64, blobs: usize) -> Arc<combined::SignedBeaconBlock<Minimal>> {
        let mut block = gloas::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        for _ in 0..blobs {
            block
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments
                .push(KzgCommitment::default());
        }
        Arc::new(combined::SignedBeaconBlock::Gloas(block))
    }

    /// Blob identifiers, column requests with their column counts, and envelope roots.
    type Asked = (Vec<(Root, u64)>, Vec<(Root, usize)>, Vec<Root>);

    /// The fetches, and the roots and indices each asks for.
    fn asked(requests: &DataRequests<Minimal>) -> Asked {
        (
            requests
                .blobs
                .iter()
                .map(|id| (id.block_root, id.index.0))
                .collect(),
            requests
                .columns
                .iter()
                .map(|id| (id.block_root, id.columns.len()))
                .collect(),
            requests.envelopes.clone(),
        )
    }

    #[test]
    fn each_fork_asks_for_its_own_data() {
        // Fixture state: Deneb at genesis, Fulu at epoch 2, Gloas at epoch 4, eight slots each.
        // The node samples columns 3 and 7, and the clock is at slot 40, in epoch 5.
        let config = ChainConfig::minimal()
            .with_forks_at_genesis(ForkName::Deneb)
            .with_fork_epoch(ForkName::Fulu, Epoch(2))
            .with_fork_epoch(ForkName::Gloas, Epoch(4));
        let sampled = [ColumnIndex(3), ColumnIndex(7)];
        let blocks = [
            deneb_block(1, 2),
            deneb_block(2, 0),
            fulu_block(17, 1),
            fulu_block(18, 0),
            gloas_block(33, 1),
            gloas_block(34, 0),
        ];
        let roots: Vec<Root> = blocks.iter().map(|block| block.block_root()).collect();
        let requests = DataRequests::of(&config, &blocks, Slot(40), &sampled);

        // Two blobs for the first Deneb block, the sampled columns of each block with blobs,
        // and both Gloas payloads, empty or not.
        assert_eq!(
            asked(&requests),
            (
                vec![(roots[0], 0), (roots[0], 1)],
                vec![(roots[2], 2), (roots[4], 2)],
                vec![roots[4], roots[5]],
            )
        );
        assert_eq!(
            requests
                .bodies()
                .iter()
                .map(|(fetch, _)| *fetch)
                .collect::<Vec<_>>(),
            [Fetch::Blobs, Fetch::Columns, Fetch::Envelopes]
        );
    }

    #[test]
    fn data_past_retention_is_not_asked_for_but_payloads_are() {
        // Fixture state: blob sidecars kept 4096 epochs, columns as long, the clock 5000 epochs on.
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Gloas);
        let current = Epoch(5_000).start_slot::<Minimal>();
        let blocks = [gloas_block(1, 3)];
        let requests = DataRequests::of(&config, &blocks, current, &[ColumnIndex(0)]);

        // The old payload is still needed for its children, its columns no longer.
        assert_eq!(
            asked(&requests),
            (Vec::new(), Vec::new(), vec![blocks[0].block_root()])
        );
    }

    #[test]
    fn a_chain_without_data_needs_no_request() {
        let config = ChainConfig::minimal();
        let blocks = [Arc::new(combined::SignedBeaconBlock::Phase0(
            phase0::SignedBeaconBlock::<Minimal>::default(),
        ))];
        let requests = DataRequests::of(&config, &blocks, Slot(1), &[ColumnIndex(0)]);
        assert_eq!(requests.bodies(), Vec::new());
    }
}
