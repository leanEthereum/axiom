//! The chain: the fork choice store, its database, and the head it selects.

mod availability;
mod database;
mod gossip;
mod handle;
mod head;

use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

pub use availability::Submission;
use availability::{AvailabilityBuffer, ReadyBlock};
use axiom_fork_choice::{DataAvailability, ExecutionStatus, ForkChoiceError, PayloadStatus, Store};
use axiom_gossip::{ChainView, GossipValidator};
use axiom_ssz::Ssz;
use axiom_state_transition::{EpochCommittees, State, Verification};
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    AggregationBits, Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, BeaconState,
    BlsSignature, ChainConfig, Checkpoint, ColumnIndex, CommitteeBits, DataColumnSidecar, Epoch,
    ForkDigest, Hash32, Preset, Root, SignedBeaconBlock, SingleAttestation, Slot,
};
pub use database::ChainDatabase;
use gossip::GossipMemory;
pub use handle::{ChainHandle, ChainStopped};
pub use head::{ChainEvent, ExecutionHead, Head};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::ChainError;

/// How many chain events a slow subscriber may fall behind before it starts losing them.
const EVENT_BACKLOG: usize = 256;

/// The node's view of the beacon chain.
///
/// # Overview
///
/// The fork choice store holds every block since finality and picks the head.
/// The database keeps blocks for good and an anchor state to resume from.
///
/// ```text
///     block ──> fork choice store ──> head ──> events: head, reorg, finalized
///                     │
///                     └── finality ──> database: anchor state, canonical index, orphans
/// ```
///
/// Every method is synchronous and runs on one thread.
/// Other services reach it through a handle.
#[derive(Debug)]
pub struct Chain<P: Preset> {
    /// The fork choice store.
    store: Store<P>,
    /// Persistent blocks and anchors.
    database: ChainDatabase<P>,
    /// The head as of the last head update.
    head: Head,
    /// Subscribers to head, reorg, and finality changes.
    events: broadcast::Sender<ChainEvent>,
    /// Gauges, counters, and timings the node exports.
    metrics: NodeMetrics,
    /// Database bytes written as of the last metrics update.
    bytes_written: u64,
    /// Blocks waiting for their custody columns.
    availability: AvailabilityBuffer<P>,
    /// What gossip validation remembers.
    gossip: GossipMemory,
    /// Committees of one epoch as the head state shuffles them, reused until the head moves.
    committees: Option<(Epoch, Root, Arc<EpochCommittees>)>,
}

impl<P: Preset> Chain<P> {
    /// A chain starting from a genesis state.
    ///
    /// The genesis block is implied by the state: an empty body committing to it.
    /// See `get_forkchoice_store` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the anchor cannot be recorded.
    pub fn from_genesis(
        config: ChainConfig,
        genesis: BeaconState<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        // The genesis header already names the body; only its state root is left blank.
        let header = &genesis.latest_block_header;
        let block = BeaconBlock {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: genesis.hash_tree_root(),
            body: BeaconBlockBody::default(),
        };
        // Genesis has no proposer, so its block carries no signature.
        let block = SignedBeaconBlock {
            message: block,
            signature: BlsSignature::default(),
        };
        Self::from_anchor(config, genesis, &block, database)
    }

    /// A chain starting from a trusted block and its post-state, as a checkpoint sync does.
    ///
    /// The anchor is recorded as finalized, so a restart resumes from it.
    ///
    /// # Errors
    ///
    /// Fails when the block does not commit to the state, or the anchor cannot be recorded.
    pub fn from_anchor(
        config: ChainConfig,
        state: BeaconState<P>,
        signed: &SignedBeaconBlock<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        let root = signed.message.hash_tree_root();
        let checkpoint = Checkpoint {
            epoch: state.current_epoch(),
            root,
        };
        let slot = signed.message.slot;
        // The anchor is trusted, so its signature is kept as given and never checked.
        let chain = Self::with_anchor(config, state, &signed.message, database)?;
        chain.database.put_block(root, signed)?;
        let anchor_state = chain
            .store
            .block_state(&root)
            .ok_or(ChainError::MissingState(root))?
            .beacon();
        chain
            .database
            .finalize(checkpoint, checkpoint, anchor_state, &[(slot, root)], &[])?;
        Ok(chain)
    }

    /// The chain a database was left with, resuming from its finalized anchor.
    ///
    /// Blocks after the anchor are not replayed; the node fetches them again from peers.
    ///
    /// # Errors
    ///
    /// Fails when the database holds no anchor, or is unreadable or inconsistent.
    pub fn resume(config: ChainConfig, database: ChainDatabase<P>) -> Result<Self, ChainError> {
        let (checkpoint, state) = database
            .finalized()?
            .ok_or(ChainError::Missing("finalized checkpoint"))?;
        let block = database
            .block(checkpoint.root)?
            .ok_or(ChainError::Missing("finalized block"))?;
        Self::with_anchor(config, state, &block.message, database)
    }

    /// Builds the store over an anchor and selects the first head.
    fn with_anchor(
        config: ChainConfig,
        state: BeaconState<P>,
        block: &BeaconBlock<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        let mut store = Store::new(config, state, block)?;
        let head = Self::read_head(&mut store)?;
        info!(slot = %head.slot, root = %head.root, "chain anchored");
        Ok(Self {
            store,
            database,
            head,
            events: broadcast::channel(EVENT_BACKLOG).0,
            metrics: NodeMetrics::detached(),
            bytes_written: 0,
            // Until told otherwise, sample every column: the strictest availability rule.
            availability: AvailabilityBuffer::new((0..P::NUMBER_OF_COLUMNS).map(ColumnIndex)),
            gossip: GossipMemory::default(),
            committees: None,
        })
    }

    /// Samples only the given columns, as this node's custody assigns.
    ///
    /// See `get_custody_groups` and `compute_columns_for_custody_group` in the Fulu DAS spec.
    #[must_use]
    pub fn with_custody(mut self, columns: impl IntoIterator<Item = ColumnIndex>) -> Self {
        self.availability = AvailabilityBuffer::new(columns);
        self
    }

    /// Records into the node's exported metrics instead of a private set.
    #[must_use]
    pub fn with_metrics(mut self, metrics: NodeMetrics) -> Self {
        self.metrics = metrics;
        // Publish the anchor's head at once rather than at the first change.
        self.record_head(self.head, true);
        self
    }

    /// A receiver of every future chain event.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.events.subscribe()
    }

    /// The head as of the latest input.
    #[must_use]
    pub const fn head(&self) -> Head {
        self.head
    }

    /// The fork choice store, for queries.
    #[must_use]
    pub const fn store(&self) -> &Store<P> {
        &self.store
    }

    /// The chain configuration.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        self.store.config()
    }

    /// The database, for queries.
    #[must_use]
    pub const fn database(&self) -> &ChainDatabase<P> {
        &self.database
    }

    /// Post-state of a block the fork choice still holds.
    #[must_use]
    pub fn state(&self, root: &Root) -> Option<&State<P>> {
        self.store.block_state(root)
    }

    /// A block by root, from the database.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub fn block(&self, root: Root) -> Result<Option<SignedBeaconBlock<P>>, ChainError> {
        self.database.block(root)
    }

    /// The root that binds signatures and topics to this chain's genesis validator set.
    #[must_use]
    pub fn genesis_validators_root(&self) -> Root {
        // Every state carries it unchanged; the head's state is always held.
        self.store
            .block_state(&self.head.root)
            .map_or(Root::ZERO, |state| state.beacon().genesis_validators_root)
    }

    /// The digest of the fork active at an epoch, which names gossip topics and tags responses.
    #[must_use]
    pub fn fork_digest(&self, epoch: Epoch) -> ForkDigest {
        self.config()
            .fork_digest(self.genesis_validators_root(), epoch)
    }

    /// Root of the canonical block proposed at a slot, if any.
    ///
    /// Since finality the head's chain decides; before it, the finalized index does.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub fn canonical_root(&self, slot: Slot) -> Result<Option<Root>, ChainError> {
        if slot > self.head.slot {
            return Ok(None);
        }
        let finalized_slot = self
            .store
            .blocks()
            .get(&self.head.finalized.root)
            .map(|node| node.slot);
        if finalized_slot.is_some_and(|finalized| slot >= finalized) {
            // The ancestor at a slot may be an earlier block when the slot was empty.
            let blocks = self.store.blocks();
            return Ok(blocks
                .ancestor(self.head.root, slot)
                .filter(|root| blocks.get(root).is_some_and(|node| node.slot == slot)));
        }
        self.database.canonical_root(slot)
    }

    /// Advances the fork choice clock.
    ///
    /// # Errors
    ///
    /// Fails when the head cannot be recomputed.
    pub fn on_tick(&mut self, time_ms: u64) -> Result<(), ChainError> {
        let epoch = self.store.current_epoch();
        self.store.on_tick(time_ms);
        if self.store.current_epoch() != epoch {
            // Messages from two epochs ago can no longer be gossiped, so forget them.
            self.gossip.seen.prune::<P>(self.store.current_epoch());
        }
        self.metrics
            .clock_slot
            .set_count(self.store.current_slot().0);
        // A new slot clears the proposer boost, which can move the head.
        self.update_head()
    }

    /// Imports a block whose payload verdict and data availability are known.
    ///
    /// # Returns
    ///
    /// The block's root.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the block or it cannot be stored.
    pub fn import_block(
        &mut self,
        block: &SignedBeaconBlock<P>,
        availability: DataAvailability,
        payload: PayloadStatus,
    ) -> Result<Root, ChainError> {
        let root = block.message.hash_tree_root();
        let timer = self.metrics.block_import_seconds.start_timer();
        if let Err(error) =
            self.store
                .import_block(block, availability, Verification::Verify, payload)
        {
            // Refused blocks fail early, so timing them would skew the import latency.
            timer.discard();
            return Err(error.into());
        }
        drop(timer);
        // Store before announcing, so any reader told of the block can fetch it.
        self.database.put_block(root, block)?;
        info!(slot = %block.message.slot, %root, "imported block");
        self.update_head()?;
        Ok(root)
    }

    /// Hands over a block that passed gossip or sync checks, with its payload verdict.
    ///
    /// The block imports now if its data is complete, or later when the last column arrives.
    ///
    /// # Errors
    ///
    /// Fails when the block is imported now and the fork choice refuses it.
    pub fn submit_block(
        &mut self,
        block: Arc<SignedBeaconBlock<P>>,
        payload: PayloadStatus,
    ) -> Result<Submission, ChainError> {
        let root = block.message.hash_tree_root();
        if self.store.blocks().contains(&root) {
            return Ok(Submission::Imported(root));
        }
        // Peers serve columns only for recent epochs, so older blocks are not sampled.
        // See the note on the retention window in the Fulu fork choice spec.
        let window = self.config().min_epochs_for_data_column_sidecars_requests;
        let epoch = block.message.slot.epoch::<P>();
        let ready = ReadyBlock { block, payload };
        if epoch.0.saturating_add(window) < self.store.current_epoch().0 {
            return self
                .import_ready(root, &ready)
                .map(|()| Submission::Imported(root));
        }
        match self.availability.offer_block(root, ready) {
            Some(ready) => self
                .import_ready(root, &ready)
                .map(|()| Submission::Imported(root)),
            None => Ok(Submission::Waiting(root)),
        }
    }

    /// Hands over a verified custody column, which may complete a waiting block.
    ///
    /// # Returns
    ///
    /// The root of the block the column released and imported, if any.
    ///
    /// # Errors
    ///
    /// Fails when a released block is refused by the fork choice.
    pub fn submit_column(
        &mut self,
        column: Arc<DataColumnSidecar<P>>,
    ) -> Result<Option<Root>, ChainError> {
        let root = column.signed_block_header.message.hash_tree_root();
        match self.availability.offer_column(root, column) {
            Some(ready) => self.import_ready(root, &ready).map(|()| Some(root)),
            None => Ok(None),
        }
    }

    /// The columns this node samples and serves.
    #[must_use]
    pub const fn custody(&self) -> &BTreeSet<ColumnIndex> {
        self.availability.custody()
    }

    /// Runs gossip validation against the chain.
    ///
    /// The validator borrows the store and the gossip memory for the duration of the check.
    pub fn validate_gossip<R>(
        &mut self,
        check: impl FnOnce(&mut GossipValidator<'_, '_, P>) -> R,
    ) -> R {
        let mut view = ChainView::new(
            &mut self.store,
            &self.gossip.unimported,
            &self.gossip.payload_statuses,
        );
        let mut validator = GossipValidator::new(&mut view, &mut self.gossip.seen);
        check(&mut validator)
    }

    /// Imports a block whose data is available, then stores its columns.
    fn import_ready(&mut self, root: Root, ready: &ReadyBlock<P>) -> Result<(), ChainError> {
        let columns = self.availability.take_columns(&root);
        match self.import_block(&ready.block, DataAvailability::Available, ready.payload) {
            Ok(_) => {
                // An earlier refusal, for want of a parent or of time, no longer holds.
                self.gossip.forget(&root);
                self.database.put_columns(root, &columns)
            }
            Err(error) => {
                // Only a block that can never import condemns its descendants on gossip.
                // A missing parent or an early arrival may still resolve.
                if Self::is_permanent(&error) {
                    let invalid_payload = matches!(ready.payload, PayloadStatus::Invalid { .. });
                    self.gossip.refuse(root, &ready.block, invalid_payload);
                }
                Err(error)
            }
        }
    }

    /// Whether a block failure would recur on every retry.
    const fn is_permanent(error: &ChainError) -> bool {
        matches!(
            error,
            ChainError::ForkChoice(
                ForkChoiceError::InvalidBlock(_)
                    | ForkChoiceError::DataUnavailable
                    | ForkChoiceError::NotDescendantOfFinalized
                    | ForkChoiceError::BeforeFinalized(_)
            )
        )
    }

    /// Start of a slot, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn slot_start_ms(&self, slot: Slot) -> u64 {
        self.store.genesis_time_ms() + slot.0 * self.config().slot_duration_ms
    }

    /// Counts a vote received on its own, outside any block.
    ///
    /// The head is not recomputed: votes arrive by the thousand each slot.
    /// The next tick or block, or an explicit update, picks up their weight.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the vote.
    pub fn on_attestation(&mut self, attestation: &Attestation<P>) -> Result<(), ChainError> {
        self.store
            .on_attestation(attestation, false, Verification::Verify)?;
        Ok(())
    }

    /// Counts one validator's vote, received alone on an attestation subnet.
    ///
    /// The vote becomes an attestation with one committee and one participant, as aggregates carry them.
    ///
    /// # Errors
    ///
    /// Fails when the attester is not in the committee named, or the fork choice refuses the vote.
    pub fn on_single_attestation(&mut self, single: &SingleAttestation) -> Result<(), ChainError> {
        let committees = self.committees_at(single.data.target.epoch)?;
        let committee = committees
            .committee(single.data.slot, single.committee_index)
            .ok_or(ChainError::InvalidVote("no such committee at the slot"))?;
        let position = committee
            .iter()
            .position(|validator| *validator == single.attester_index)
            .ok_or(ChainError::InvalidVote("attester not in the committee"))?;

        // One committee bit, and one participant bit at the attester's place in that committee.
        //
        //     committee 2 of the slot: [v9, v4, v7]   attester v4   ->   aggregation bits 010
        let mut aggregation_bits = AggregationBits::<P>::with_len(committee.len())
            .map_err(|_| ChainError::InvalidVote("committee larger than the bitfield bound"))?;
        aggregation_bits.set(position, true);
        let mut committee_bits = CommitteeBits::<P>::default();
        let index = single.committee_index.as_usize();
        if single.committee_index.0 >= P::MAX_COMMITTEES_PER_SLOT {
            return Err(ChainError::InvalidVote(
                "committee index past the slot's committees",
            ));
        }
        committee_bits.set(index, true);
        let attestation = Attestation {
            aggregation_bits,
            data: single.data.clone(),
            signature: single.signature,
            committee_bits,
        };
        // The signature is checked again against the committee the store resolves.
        // A committee read from a fork with another shuffling then fails instead of crediting the wrong validator.
        self.store
            .on_attestation(&attestation, false, Verification::Verify)?;
        Ok(())
    }

    /// Committees of an epoch as the head state shuffles them.
    ///
    /// Shuffling walks every validator, so the result is kept until the head changes.
    fn committees_at(&mut self, epoch: Epoch) -> Result<Arc<EpochCommittees>, ChainError> {
        if let Some((cached, root, committees)) = &self.committees
            && *cached == epoch
            && *root == self.head.root
        {
            return Ok(Arc::clone(committees));
        }
        let state = self
            .store
            .block_state(&self.head.root)
            .ok_or(ChainError::MissingState(self.head.root))?;
        let committees = Arc::new(EpochCommittees::compute(state.beacon(), epoch));
        self.committees = Some((epoch, self.head.root, Arc::clone(&committees)));
        Ok(committees)
    }

    /// Removes the weight of validators an attester slashing proves to have equivocated.
    ///
    /// # Errors
    ///
    /// Fails when the slashing does not prove an equivocation.
    pub fn on_attester_slashing(
        &mut self,
        slashing: &AttesterSlashing<P>,
    ) -> Result<(), ChainError> {
        self.store
            .on_attester_slashing(slashing, Verification::Verify)?;
        Ok(())
    }

    /// Applies the engine's later verdict on a block imported optimistically.
    ///
    /// # Errors
    ///
    /// Fails when the head cannot be recomputed.
    pub fn on_payload_verdict(
        &mut self,
        root: Root,
        verdict: PayloadStatus,
    ) -> Result<(), ChainError> {
        match verdict {
            PayloadStatus::Valid => self.store.on_valid_payload(root),
            PayloadStatus::Invalid { latest_valid_hash } => {
                warn!(%root, "engine found an invalid payload");
                self.store.invalidate_after(root, latest_valid_hash);
            }
            PayloadStatus::NotValidated => return Ok(()),
        }
        // Invalid blocks leave the viable set, which can move the head.
        self.update_head()
    }

    /// Recomputes the head and announces what changed.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice has no state for its justified checkpoint or head.
    pub fn update_head(&mut self) -> Result<(), ChainError> {
        let previous = self.head;
        let timer = self.metrics.fork_choice_seconds.start_timer();
        let head = Self::read_head(&mut self.store)?;
        drop(timer);
        if head == previous {
            return Ok(());
        }

        // A head off the previous head's chain is a reorg; measure it before pruning can hide it.
        let reorg = (head.root != previous.root
            && !self.store.blocks().is_ancestor(head.root, previous.root))
        .then(|| self.reorg_depth(previous, head));

        // Invariant: finality reaches the disk before the head moves.
        // A failed write leaves the head as it was, so the next update tries again.
        let finalized = head.finalized.epoch > previous.finalized.epoch;
        if finalized {
            self.finalize(previous.finalized, head.finalized)?;
        }

        self.head = head;
        self.record_head(head, head.slot.epoch::<P>() != previous.slot.epoch::<P>());
        if let Some(depth) = reorg {
            warn!(from = %previous.root, to = %head.root, depth, "chain reorganized");
            self.metrics.reorgs.inc();
            self.announce(ChainEvent::Reorg {
                from: previous.root,
                to: head.root,
                depth,
            });
        }
        if head.root != previous.root {
            info!(slot = %head.slot, root = %head.root, optimistic = head.optimistic, "new head");
        }
        self.announce(ChainEvent::Head(head));

        if finalized {
            // Waiting blocks and refused ones at or before finality can never matter again.
            let finalized_slot = head.finalized.epoch.start_slot::<P>();
            self.availability.prune(finalized_slot);
            self.gossip.prune(finalized_slot);
            info!(epoch = %head.finalized.epoch, root = %head.finalized.root, "finalized");
            self.announce(ChainEvent::Finalized(head.finalized));
        }
        Ok(())
    }

    /// Persists a new finality, then forgets what it excluded.
    ///
    /// The database write comes first: if it fails, the store keeps everything and nothing is lost.
    fn finalize(&mut self, previous: Checkpoint, finalized: Checkpoint) -> Result<(), ChainError> {
        // Walk back from the new finalized block to the old one: the newly finalized chain.
        let blocks = self.store.blocks();
        let mut chain = Vec::new();
        let mut current = finalized.root;
        while current != previous.root {
            let Some(node) = blocks.get(&current) else {
                break;
            };
            chain.push((node.slot, current));
            current = node.parent_root;
        }
        let canonical: HashSet<Root> = chain.iter().map(|(_, root)| *root).collect();

        // Blocks neither on the finalized chain nor after it are orphaned forks.
        let orphans: Vec<Root> = blocks
            .iter()
            .map(|(root, _)| *root)
            .filter(|root| {
                !canonical.contains(root)
                    && *root != previous.root
                    && !blocks.is_ancestor(*root, finalized.root)
            })
            .collect();
        let state = self
            .store
            .block_state(&finalized.root)
            .ok_or(ChainError::MissingState(finalized.root))?
            .beacon();
        self.database
            .finalize(previous, finalized, state, &chain, &orphans)?;

        // Only now that the disk agrees, drop the excluded blocks from memory.
        self.store.prune();
        Ok(())
    }

    /// Blocks on the old head's chain after the common ancestor with the new head.
    fn reorg_depth(&self, from: Head, to: Head) -> u64 {
        let blocks = self.store.blocks();
        let mut depth = 0;
        let mut current = from.root;
        while let Some(node) = blocks.get(&current) {
            if blocks.is_ancestor(to.root, current) {
                break;
            }
            depth += 1;
            current = node.parent_root;
        }
        depth
    }

    /// Reads the head and its checkpoints from the store.
    fn read_head(store: &mut Store<P>) -> Result<Head, ChainError> {
        let root = store.head()?;
        let node = *store
            .blocks()
            .get(&root)
            .ok_or(ChainError::MissingState(root))?;
        let state = store
            .block_state(&root)
            .ok_or(ChainError::MissingState(root))?;
        let justified = store.justified_checkpoint();
        let finalized = store.finalized_checkpoint();

        // A block's post-state caches the header of its own payload.
        let payload_hash = |root: &Root| -> Hash32 {
            store.block_state(root).map_or(Hash32::ZERO, |state| {
                state.beacon().latest_execution_payload_header.block_hash
            })
        };
        Ok(Head {
            root,
            slot: node.slot,
            optimistic: node.status != ExecutionStatus::Valid,
            justified,
            finalized,
            execution: ExecutionHead {
                head: state.beacon().latest_execution_payload_header.block_hash,
                safe: payload_hash(&justified.root),
                finalized: payload_hash(&finalized.root),
            },
        })
    }

    /// Publishes the head's numbers to the metrics.
    ///
    /// Counting active validators walks the whole registry, so it runs only on a new epoch.
    fn record_head(&mut self, head: Head, new_epoch: bool) {
        let metrics = &self.metrics;
        metrics.head_slot.set_count(head.slot.0);
        metrics.finalized_epoch.set_count(head.finalized.epoch.0);
        metrics
            .current_justified_epoch
            .set_count(head.justified.epoch.0);
        if let Some(state) = self.store.block_state(&head.root) {
            let beacon = state.beacon();
            metrics
                .previous_justified_epoch
                .set_count(beacon.previous_justified_checkpoint.epoch.0);
            metrics
                .processed_deposits
                .set_count(beacon.eth1_deposit_index);
            if new_epoch {
                let epoch = beacon.current_epoch();
                let active = beacon
                    .validators
                    .iter()
                    .filter(|validator| validator.is_active_at(epoch))
                    .count();
                metrics.current_active_validators.set_count(active as u64);
            }
        }
        // The store counts bytes since it opened; the counter takes the increase.
        let written = self.database.bytes_written();
        metrics
            .store_bytes_written
            .inc_by(written.saturating_sub(self.bytes_written));
        self.bytes_written = written;
    }

    /// Sends an event to every subscriber.
    fn announce(&self, event: ChainEvent) {
        // Having no subscriber is normal, so a failed send is not an error.
        let _unheard = self.events.send(event);
    }
}
