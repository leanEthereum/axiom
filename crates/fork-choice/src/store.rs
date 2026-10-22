//! The fork choice store: what a node knows, the clock it knows it by, and the events that grow it.

use std::collections::HashMap;

use axiom_ssz::Ssz;
use axiom_state_transition::{
    BlockProcessor, EpochProcessor, EpochStep, State, StateError, Verification,
};
use axiom_types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, ChainConfig, Checkpoint, Epoch,
    Hash32, IndexedAttestation, Preset, Root, SignedBeaconBlock, Slot, SlotClock,
};

use crate::{
    BlockNode, BlockTree, DataAvailability, ExecutionStatus, ForkChoiceError, Ghost, LatestMessage,
    PayloadStatus, Votes, checkpoints::Checkpoints, proposer_head::LateHeadReorg,
};

/// Everything the fork choice rule reads: blocks, states, votes, checkpoints, and time.
///
/// # Overview
///
/// The store is a pure state machine driven by four kinds of events.
///
/// ```text
/// on_tick              time advances
/// on_block             a block arrives
/// on_attestation       a vote arrives
/// on_attester_slashing equivocators are proven
/// ```
///
/// The head is a pure function of the store, see `get_head` in the phase0 fork choice spec.
/// Head selection runs on a view of the store through its justified state.
///
/// # Invariants
///
/// Every block in the tree has its post-state stored.
/// A handler that fails leaves the store unchanged.
#[derive(Clone, Debug)]
pub struct Store<P: Preset> {
    /// The chain configuration.
    pub(crate) config: ChainConfig,
    /// Genesis and the slot length.
    pub(crate) clock: SlotClock,
    /// Current time, in milliseconds since the Unix epoch.
    pub(crate) time_ms: u64,
    /// Realized and unrealized checkpoints.
    pub(crate) checkpoints: Checkpoints,
    /// Block that holds the proposer boost in the current slot, or zero.
    pub(crate) proposer_boost_root: Root,
    /// Accepted blocks.
    pub(crate) blocks: BlockTree,
    /// Post-state of each accepted block.
    pub(crate) block_states: HashMap<Root, State<P>>,
    /// Whether each block arrived on time in its own slot.
    pub(crate) block_timeliness: HashMap<Root, bool>,
    /// States at checkpoint boundaries, by checkpoint.
    pub(crate) checkpoint_states: HashMap<Checkpoint, State<P>>,
    /// Latest votes and equivocators.
    pub(crate) votes: Votes,
    /// Justified checkpoint each block would realize at its next epoch boundary.
    pub(crate) unrealized_justifications: HashMap<Root, Checkpoint>,
}

impl<P: Preset> Store<P> {
    /// A store anchored at a trusted state and the block it is the post-state of.
    ///
    /// The anchor is genesis for a full sync, or a finalized checkpoint for a checkpoint sync.
    /// See `get_forkchoice_store` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the block does not commit to the state.
    pub fn new(
        config: ChainConfig,
        anchor_state: BeaconState<P>,
        anchor_block: &BeaconBlock<P>,
    ) -> Result<Self, ForkChoiceError> {
        if anchor_block.state_root != anchor_state.hash_tree_root() {
            return Err(ForkChoiceError::AnchorMismatch);
        }
        let anchor_root = anchor_block.hash_tree_root();
        let checkpoint = Checkpoint {
            epoch: anchor_state.current_epoch(),
            root: anchor_root,
        };
        let clock = SlotClock::new(
            anchor_state.genesis_time.saturating_mul(1000),
            config.slot_duration_ms,
        );
        let time_ms = clock.slot_start_ms(anchor_state.slot);
        let state = State::new(anchor_state);

        Ok(Self {
            config,
            clock,
            time_ms,
            checkpoints: Checkpoints::at(checkpoint),
            proposer_boost_root: Root::ZERO,
            blocks: BlockTree::new(
                anchor_root,
                BlockNode {
                    slot: anchor_block.slot,
                    parent_root: anchor_block.parent_root,
                    proposer_index: anchor_block.proposer_index,
                    execution_block_hash: anchor_block.body.execution_payload.block_hash,
                    status: ExecutionStatus::Valid,
                },
            ),
            block_states: HashMap::from([(anchor_root, state.clone())]),
            block_timeliness: HashMap::new(),
            checkpoint_states: HashMap::from([(checkpoint, state)]),
            votes: Votes::default(),
            unrealized_justifications: HashMap::from([(anchor_root, checkpoint)]),
        })
    }

    /// The chain configuration.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Genesis and the slot length.
    #[must_use]
    pub const fn slot_clock(&self) -> SlotClock {
        self.clock
    }

    /// Current time, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn time_ms(&self) -> u64 {
        self.time_ms
    }

    /// Justified checkpoint LMD-GHOST starts from.
    #[must_use]
    pub const fn justified_checkpoint(&self) -> Checkpoint {
        self.checkpoints.justified()
    }

    /// Latest finalized checkpoint.
    #[must_use]
    pub const fn finalized_checkpoint(&self) -> Checkpoint {
        self.checkpoints.finalized()
    }

    /// Block holding the proposer boost, or zero.
    #[must_use]
    pub const fn proposer_boost_root(&self) -> Root {
        self.proposer_boost_root
    }

    /// The tree of accepted blocks.
    #[must_use]
    pub const fn blocks(&self) -> &BlockTree {
        &self.blocks
    }

    /// Post-state of an accepted block.
    #[must_use]
    pub fn block_state(&self, root: &Root) -> Option<&State<P>> {
        self.block_states.get(root)
    }

    /// The slot the clock is in.
    ///
    /// See `get_current_slot` in the phase0 fork choice spec.
    #[must_use]
    pub const fn current_slot(&self) -> Slot {
        self.clock.slot_at(self.time_ms)
    }

    /// The epoch the clock is in.
    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.current_slot().epoch::<P>()
    }

    /// The block that is the checkpoint of an epoch on a block's chain.
    ///
    /// See `get_checkpoint_block` in the phase0 fork choice spec.
    #[must_use]
    pub fn checkpoint_block(&self, root: Root, epoch: Epoch) -> Option<Root> {
        self.blocks.ancestor(root, epoch.start_slot::<P>())
    }

    /// The justified checkpoint a block would vote with as the head.
    ///
    /// A block from a past epoch is pulled up: its unrealized justification counts.
    /// See `get_voting_source` in the phase0 fork choice spec.
    #[must_use]
    pub fn voting_source(&self, root: Root) -> Option<Checkpoint> {
        let node = self.blocks.get(&root)?;
        if self.current_epoch() > node.slot.epoch::<P>() {
            self.unrealized_justifications.get(&root).copied()
        } else {
            self.block_states
                .get(&root)
                .map(|state| state.beacon().current_justified_checkpoint)
        }
    }

    /// The store seen through its justified checkpoint state, for head selection.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn ghost(&mut self) -> Result<Ghost<'_, P>, ForkChoiceError> {
        let justified = self.checkpoints.justified();
        self.checkpoint_state(justified)?;
        let state = self
            .checkpoint_states
            .get(&justified)
            .ok_or(ForkChoiceError::MissingState(justified.root))?;
        Ok(Ghost::new(self, state.beacon()))
    }

    /// The head of the chain.
    ///
    /// See `get_head` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn head(&mut self) -> Result<Root, ForkChoiceError> {
        Ok(self.ghost()?.head())
    }

    /// The block a proposer at a slot should build on: the head, or a late head's parent.
    ///
    /// See `get_proposer_head` in the Fulu fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the head still holds the proposer boost, or its state is missing.
    pub fn proposer_head(&mut self, head: Root, slot: Slot) -> Result<Root, ForkChoiceError> {
        if self.proposer_boost_root == head {
            return Err(ForkChoiceError::HeadStillBoosted);
        }
        let head_block = *self
            .blocks
            .get(&head)
            .ok_or(ForkChoiceError::MissingState(head))?;
        let parent_block = *self
            .blocks
            .get(&head_block.parent_root)
            .ok_or(ForkChoiceError::MissingState(head_block.parent_root))?;
        let head_committees = self
            .block_states
            .get_mut(&head)
            .ok_or(ForkChoiceError::MissingState(head))?
            .committees(head_block.slot.epoch::<P>())?;
        let ghost = self.ghost()?;
        Ok(
            LateHeadReorg::new(ghost, head, head_block, parent_block, head_committees)
                .parent_for(slot),
        )
    }

    /// Advances the clock, running the per-slot updates of every slot it crosses.
    ///
    /// See `on_tick` in the phase0 fork choice spec.
    pub fn on_tick(&mut self, time_ms: u64) {
        let tick_slot = self.clock.slot_at(time_ms);
        while self.current_slot() < tick_slot {
            let next = self.clock.slot_start_ms(self.current_slot() + 1);
            self.on_tick_per_slot(next);
        }
        self.on_tick_per_slot(time_ms);
    }

    /// Accepts a block: checks its place in the tree, runs it, and records its post-state.
    ///
    /// See `on_block` in the Fulu fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the parent is unknown, the block is from the future or before finality,
    /// its data is unavailable, or the state transition rejects it.
    pub fn on_block(
        &mut self,
        signed_block: &SignedBeaconBlock<P>,
        availability: DataAvailability,
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        let block = &signed_block.message;
        let root = block.hash_tree_root();
        if self.blocks.contains(&root) {
            return Ok(());
        }

        let parent_state = self
            .block_states
            .get(&block.parent_root)
            .ok_or(ForkChoiceError::UnknownParent(block.parent_root))?;
        let current = self.current_slot();
        if block.slot > current {
            return Err(ForkChoiceError::FutureBlock {
                slot: block.slot,
                current,
            });
        }
        let finalized = self.checkpoints.finalized();
        if block.slot <= finalized.epoch.start_slot::<P>() {
            return Err(ForkChoiceError::BeforeFinalized(block.slot));
        }
        if self.checkpoint_block(block.parent_root, finalized.epoch) != Some(finalized.root) {
            return Err(ForkChoiceError::NotDescendantOfFinalized);
        }
        if availability == DataAvailability::Unavailable {
            return Err(ForkChoiceError::DataUnavailable);
        }

        let mut state = parent_state.clone();
        // An invalid verdict condemns optimistic ancestors too, even though this block is refused.
        if let PayloadStatus::Invalid { latest_valid_hash } = payload {
            self.blocks
                .invalidate_after(block.parent_root, latest_valid_hash);
        }
        state
            .state_transition(&self.config, signed_block, verification, &payload)
            .map_err(ForkChoiceError::InvalidBlock)?;

        // The head before this block decides whether it may take the proposer boost.
        let head = self.head()?;
        let justified = state.beacon().current_justified_checkpoint;
        let finalized = state.beacon().finalized_checkpoint;

        self.blocks.insert(
            root,
            BlockNode {
                slot: block.slot,
                parent_root: block.parent_root,
                proposer_index: block.proposer_index,
                execution_block_hash: block.body.execution_payload.block_hash,
                status: if payload == PayloadStatus::Valid {
                    ExecutionStatus::Valid
                } else {
                    ExecutionStatus::Optimistic
                },
            },
        );
        self.block_states.insert(root, state);
        if payload == PayloadStatus::Valid {
            self.blocks.mark_valid(root);
        }
        self.record_block_timeliness(root, block.slot);
        self.update_proposer_boost_root(head, root);
        self.checkpoints.update(justified, finalized);
        self.compute_pulled_up_tip(root)
    }

    /// Accepts a block, then the votes and attester slashings it carries.
    ///
    /// A vote or slashing a block carries may be stale or already known.
    /// Rejecting one of them never rejects the block, so their errors are dropped.
    ///
    /// This is how the spec's test harness and every client feed a block in.
    ///
    /// # Errors
    ///
    /// Fails when the block itself is refused, as the block handler alone would.
    pub fn import_block(
        &mut self,
        signed_block: &SignedBeaconBlock<P>,
        availability: DataAvailability,
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        self.on_block(signed_block, availability, verification, payload)?;

        // Votes inside a block skip the timing rule, since a block may carry old votes.
        let body = &signed_block.message.body;
        for attestation in &body.attestations {
            let _ignored = self.on_attestation(attestation, true, verification);
        }
        // Equivocation evidence removes the offenders' weight from every branch.
        for slashing in &body.attester_slashings {
            let _ignored = self.on_attester_slashing(slashing, verification);
        }
        Ok(())
    }

    /// Records a block and its post-state, skipping the timing, finality, and boost rules.
    ///
    /// This replays a chain whose blocks were already validated elsewhere.
    /// A checkpoint sync and a spec vector's history both do so.
    pub fn insert_validated_block(&mut self, block: &BeaconBlock<P>, state: State<P>) {
        let root = block.hash_tree_root();
        let justified = state.beacon().current_justified_checkpoint;
        self.blocks.insert(
            root,
            BlockNode {
                slot: block.slot,
                parent_root: block.parent_root,
                proposer_index: block.proposer_index,
                execution_block_hash: block.body.execution_payload.block_hash,
                status: ExecutionStatus::Valid,
            },
        );
        self.block_states.insert(root, state);
        self.unrealized_justifications.insert(root, justified);
    }

    /// Accepts an attestation's votes.
    ///
    /// Votes from blocks skip the timing check, since a block may carry old votes.
    /// See `on_attestation` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the vote is out of time, names unknown or inconsistent blocks, or does not verify.
    pub fn on_attestation(
        &mut self,
        attestation: &Attestation<P>,
        is_from_block: bool,
        verification: Verification,
    ) -> Result<(), ForkChoiceError> {
        self.validate_on_attestation(attestation, is_from_block)?;

        let target = attestation.data.target;
        let config = self.config.clone();
        let state = self.checkpoint_state(target)?;
        let attesters = state
            .attesting_indices(attestation)
            .map_err(ForkChoiceError::InvalidAttestation)?;
        let indexed = IndexedAttestation::<P> {
            attesting_indices: attesters
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| ForkChoiceError::State(StateError::ListFull))?,
            data: attestation.data.clone(),
            signature: attestation.signature,
        };
        let mut processor = BlockProcessor::new(state, &config, verification);
        processor
            .verify_indexed_attestation(&indexed)
            .and_then(|()| processor.finish())
            .map_err(ForkChoiceError::InvalidAttestation)?;

        self.votes.record(
            attesters,
            LatestMessage {
                epoch: target.epoch,
                root: attestation.data.beacon_block_root,
            },
        );
        Ok(())
    }

    /// Records the validators an attester slashing proves to have equivocated.
    ///
    /// Their votes stop counting immediately, before any block includes the slashing.
    /// See `on_attester_slashing` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the votes are not slashable or do not verify.
    pub fn on_attester_slashing(
        &mut self,
        slashing: &AttesterSlashing<P>,
        verification: Verification,
    ) -> Result<(), ForkChoiceError> {
        if !slashing
            .attestation_1
            .data
            .is_slashable_with(&slashing.attestation_2.data)
        {
            return Err(ForkChoiceError::NotSlashable);
        }
        let justified_root = self.checkpoints.justified().root;
        let config = self.config.clone();
        let state = self
            .block_states
            .get_mut(&justified_root)
            .ok_or(ForkChoiceError::MissingState(justified_root))?;
        let mut processor = BlockProcessor::new(state, &config, verification);
        processor
            .verify_indexed_attestation(&slashing.attestation_1)
            .and_then(|()| processor.verify_indexed_attestation(&slashing.attestation_2))
            .and_then(|()| processor.finish())
            .map_err(ForkChoiceError::InvalidAttestation)?;

        self.votes.mark_equivocating(slashing.common_signers());
        Ok(())
    }

    /// Invalidates the optimistic blocks an invalid payload condemns.
    ///
    /// See "How to apply latestValidHash" in the Bellatrix optimistic sync spec.
    pub fn invalidate_after(&mut self, parent: Root, latest_valid_hash: Option<Hash32>) {
        self.blocks.invalidate_after(parent, latest_valid_hash);
    }

    /// Records that the engine validated a block's payload, after an optimistic import.
    ///
    /// A valid payload implies valid ancestors, so they turn valid too.
    /// See the Bellatrix optimistic sync spec.
    pub fn on_valid_payload(&mut self, root: Root) {
        self.blocks.mark_valid(root);
    }

    /// Drops every block that does not descend from the finalized block, with its state.
    ///
    /// No head can leave the finalized block's subtree, so nothing dropped can matter again.
    /// The spec's store grows forever; a node prunes to keep memory bounded.
    ///
    /// # Returns
    ///
    /// The roots dropped, so the caller can also forget them elsewhere.
    pub fn prune(&mut self) -> Vec<Root> {
        let finalized = self.checkpoints.finalized();

        // The finalized block becomes the new anchor of the tree.
        let dropped = self.blocks.retain_subtree(finalized.root);
        for root in &dropped {
            self.block_states.remove(root);
            self.block_timeliness.remove(root);
            self.unrealized_justifications.remove(root);
        }

        // Justified checkpoints never precede the finalized one, so older states are unreachable.
        self.checkpoint_states
            .retain(|checkpoint, _| checkpoint.epoch >= finalized.epoch);
        dropped
    }

    /// The state at a checkpoint: its block's post-state, advanced to the epoch start.
    ///
    /// See `store_target_checkpoint_state` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the checkpoint block's state is missing.
    pub(crate) fn checkpoint_state(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<&mut State<P>, ForkChoiceError> {
        if !self.checkpoint_states.contains_key(&checkpoint) {
            let mut state = self
                .block_states
                .get(&checkpoint.root)
                .ok_or(ForkChoiceError::MissingState(checkpoint.root))?
                .clone();
            let start = checkpoint.epoch.start_slot::<P>();
            if state.beacon().slot < start {
                state.process_slots(&self.config, start)?;
            }
            self.checkpoint_states.insert(checkpoint, state);
        }
        self.checkpoint_states
            .get_mut(&checkpoint)
            .ok_or(ForkChoiceError::MissingState(checkpoint.root))
    }

    /// Moves the clock within one slot, or onto the start of the next.
    ///
    /// A new slot clears the proposer boost.
    /// A new epoch realizes the checkpoints that were only pulled up so far.
    fn on_tick_per_slot(&mut self, time_ms: u64) {
        let previous_slot = self.current_slot();
        self.time_ms = time_ms;
        let current_slot = self.current_slot();

        if current_slot > previous_slot {
            self.proposer_boost_root = Root::ZERO;
            if current_slot.is_epoch_start::<P>() {
                self.checkpoints.realize();
            }
        }
    }

    /// Checks an attestation against the store's view, before any state is touched.
    ///
    /// See `validate_on_attestation` in the phase0 fork choice spec.
    fn validate_on_attestation(
        &self,
        attestation: &Attestation<P>,
        is_from_block: bool,
    ) -> Result<(), ForkChoiceError> {
        let data = &attestation.data;
        let target = data.target;

        if !is_from_block {
            let current = self.current_epoch();
            if target.epoch != current && target.epoch != current.saturating_sub(1) {
                return Err(ForkChoiceError::AttestationEpochOutOfRange(target.epoch));
            }
        }
        if target.epoch != data.slot.epoch::<P>() {
            return Err(ForkChoiceError::AttestationTargetSlotMismatch);
        }
        if !self.blocks.contains(&target.root) {
            return Err(ForkChoiceError::UnknownTarget(target.root));
        }
        let head = self
            .blocks
            .get(&data.beacon_block_root)
            .ok_or(ForkChoiceError::UnknownHead(data.beacon_block_root))?;
        if head.slot > data.slot {
            return Err(ForkChoiceError::HeadFromFuture);
        }
        // The LMD vote must agree with the FFG vote: the target is the head's checkpoint.
        if self.checkpoint_block(data.beacon_block_root, target.epoch) != Some(target.root) {
            return Err(ForkChoiceError::TargetNotHeadCheckpoint);
        }
        // Timing: a vote only counts from the slot after it was cast.
        if self.current_slot() < data.slot + 1 {
            return Err(ForkChoiceError::AttestationFromFuture(data.slot));
        }
        Ok(())
    }

    /// Records whether a block arrived in its own slot, before the attestation deadline.
    ///
    /// See `record_block_timeliness` in the phase0 fork choice spec.
    fn record_block_timeliness(&mut self, root: Root, slot: Slot) {
        let deadline = self.clock.component_ms(self.config.attestation_due_bps);
        let timely =
            self.current_slot() == slot && self.clock.time_into_slot_ms(self.time_ms) < deadline;
        self.block_timeliness.insert(root, timely);
    }

    /// Gives a block the proposer boost when it is timely, first, and on the head's shuffling.
    ///
    /// Proposer boost blunts the balancing attack.
    /// An adversary can no longer keep two forks tied by releasing votes at the right time.
    ///
    /// See `update_proposer_boost_root` in the phase0 fork choice spec.
    fn update_proposer_boost_root(&mut self, head: Root, root: Root) {
        let is_first_block = self.proposer_boost_root == Root::ZERO;
        let is_timely = self.block_timeliness.get(&root).copied().unwrap_or(false);
        let epoch = self.current_epoch();
        let same_shuffling = self.blocks.shuffling_dependent_root::<P>(head, epoch)
            == self.blocks.shuffling_dependent_root::<P>(root, epoch);
        if is_timely && is_first_block && same_shuffling {
            self.proposer_boost_root = root;
        }
    }

    /// Records the checkpoints a block would realize at its next epoch boundary.
    ///
    /// A block from a past epoch realizes them already, so the store adopts them now.
    /// See `compute_pulled_up_tip` in the phase0 fork choice spec.
    fn compute_pulled_up_tip(&mut self, root: Root) -> Result<(), ForkChoiceError> {
        let mut state = self
            .block_states
            .get(&root)
            .ok_or(ForkChoiceError::MissingState(root))?
            .clone();
        EpochProcessor::new(&mut state, &self.config)
            .run(EpochStep::JustificationAndFinalization)?;
        let justified = state.beacon().current_justified_checkpoint;
        let finalized = state.beacon().finalized_checkpoint;

        self.unrealized_justifications.insert(root, justified);
        self.checkpoints.update_unrealized(justified, finalized);

        let block_epoch = self
            .blocks
            .get(&root)
            .map_or(Epoch::GENESIS, |node| node.slot.epoch::<P>());
        if block_epoch < self.current_epoch() {
            self.checkpoints.update(justified, finalized);
        }
        Ok(())
    }
}
