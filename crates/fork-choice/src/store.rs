//! The fork choice store: what a node knows, the clock it knows it by, and the events that grow it.

use std::collections::HashMap;

use axiom_state_transition::{
    BlockProcessor, EpochStep, State, Verification, gloas::ptc::PtcWindow,
};
use axiom_types::{
    BlsSignature, ChainConfig, Epoch, Gwei, Hash32, Preset, Root, Slot, SlotClock, ValidatorIndex,
    accessors::{CoreState, ForkState},
    bellatrix::PowBlock,
    combined,
    constants::DOMAIN_PTC_ATTESTER,
    gloas::{self, PayloadAttestation, PayloadAttestationMessage, SignedExecutionPayloadEnvelope},
    phase0::Checkpoint,
    vote::{CommitteeVote, ConflictingVotes, PayloadClaim},
};

use crate::{
    BlockNode, BlockTree, DataAvailability, ExecutionStatus, ForkChoiceError, ForkChoiceNode,
    Ghost, LatestMessage, NodePayload, PayloadStatus, PayloadVotes, VoteOrder, Votes,
    bellatrix::PowChain,
    checkpoints::Checkpoints,
    gloas::{BoostParent, PayloadGhost, PtcVotes},
    proposer_head::LateHeadReorg,
    timeliness::Timeliness,
};

/// Everything the fork choice rule reads: blocks, states, votes, checkpoints, and time.
///
/// # Overview
///
/// The store is a pure state machine driven by events.
///
/// ```text
/// on_tick                          time advances
/// on_block                         a block arrives
/// on_attestation                   a vote arrives
/// on_attester_slashing             equivocators are proven
/// on_execution_payload_envelope    a Gloas payload is revealed
/// on_payload_attestation_message   a payload committee member votes
/// ```
///
/// The head is a pure function of the store, see `get_head` in the phase0 fork choice spec.
/// Head selection runs on a view of the store through its justified state.
///
/// Blocks and states of every fork live side by side, behind the combined enums.
/// The fork of the current slot picks the head rule, once, at the boundary.
/// From Gloas on the head walk weighs payload variants, before it blocks alone.
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
    /// When each block arrived, against its slot's deadlines.
    pub(crate) block_timeliness: HashMap<Root, Timeliness>,
    /// States at checkpoint boundaries, by checkpoint.
    pub(crate) checkpoint_states: HashMap<Checkpoint, State<P>>,
    /// Latest votes and equivocators.
    pub(crate) votes: Votes,
    /// Justified checkpoint each block would realize at its next epoch boundary.
    pub(crate) unrealized_justifications: HashMap<Root, Checkpoint>,
    /// The payload timeliness committee's votes, from Gloas on.
    pub(crate) ptc: PtcVotes,
    /// Proof-of-work blocks the merge transition check reads.
    pub(crate) pow_chain: PowChain,
}

impl<P: Preset> Store<P> {
    /// A store anchored at a trusted state and the block it is the post-state of.
    ///
    /// The anchor is genesis for a full sync, or a finalized checkpoint for a checkpoint sync.
    /// See `get_forkchoice_store` in the phase0 and Gloas fork choice specs.
    ///
    /// # Errors
    ///
    /// Fails when the block does not commit to the state.
    pub fn new(
        config: ChainConfig,
        state: State<P>,
        anchor_block: &combined::BeaconBlock<P>,
    ) -> Result<Self, ForkChoiceError> {
        let computed = state.hash_tree_root();
        if anchor_block.state_root() != computed {
            return Err(ForkChoiceError::AnchorMismatch {
                claimed: anchor_block.state_root(),
                computed,
            });
        }
        let anchor_root = anchor_block.hash_tree_root();
        let beacon = state.beacon();
        let checkpoint = Checkpoint {
            epoch: beacon.current_epoch(),
            root: anchor_root,
        };
        let clock = SlotClock::new(
            beacon.genesis_time().saturating_mul(1000),
            config.slot_duration_ms,
        );
        let time_ms = clock.slot_start_ms(beacon.slot());
        let mut ptc = PtcVotes::default();
        if anchor_block.fork_name().separates_payloads() {
            ptc.open::<P>(anchor_root);
        }

        Ok(Self {
            config,
            clock,
            time_ms,
            checkpoints: Checkpoints::at(checkpoint),
            proposer_boost_root: Root::ZERO,
            blocks: BlockTree::new(
                anchor_root,
                BlockNode::of(anchor_block, ExecutionStatus::Valid),
            ),
            block_states: HashMap::from([(anchor_root, state.clone())]),
            block_timeliness: HashMap::from([(anchor_root, Timeliness::ANCHOR)]),
            checkpoint_states: HashMap::from([(checkpoint, state)]),
            votes: Votes::default(),
            unrealized_justifications: HashMap::from([(anchor_root, checkpoint)]),
            ptc,
            pow_chain: PowChain::default(),
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

    /// The payload timeliness committee's votes on a Gloas block.
    #[must_use]
    pub fn payload_votes(&self, root: &Root) -> Option<&PayloadVotes> {
        self.ptc.of(root)
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
                .map(|state| state.beacon().current_justified_checkpoint())
        }
    }

    /// The store seen through its justified checkpoint state, block by block.
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

    /// The store seen through its justified checkpoint state, node by node, as Gloas weighs it.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state or the boosted block's parent state is missing.
    pub fn payload_ghost(&mut self) -> Result<PayloadGhost<'_, P>, ForkChoiceError> {
        // The parent of the boosted block may lose its boost if weak: fetch its committees first.
        let boost_parent = self.boost_parent();
        let committees = match &boost_parent {
            Some((root, block)) => Some((
                *root,
                *block,
                self.block_states
                    .get_mut(root)
                    .ok_or(ForkChoiceError::MissingState(*root))?
                    .committees(block.slot.epoch::<P>())?,
            )),
            None => None,
        };
        let ghost = self.ghost()?;
        let parent = committees
            .as_ref()
            .map(|(root, block, committees)| BoostParent {
                root: *root,
                block: *block,
                committees,
            });
        Ok(PayloadGhost::new(ghost, parent))
    }

    /// The head of the chain, with what the chain does with the head's payload.
    ///
    /// Before Gloas the head is a block carrying its payload, so its node is full.
    /// See `get_head` in the phase0 and Gloas fork choice specs.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn head(&mut self) -> Result<ForkChoiceNode, ForkChoiceError> {
        if self.weighs_payloads() {
            return Ok(self.payload_ghost()?.head());
        }
        Ok(ForkChoiceNode {
            root: self.ghost()?.head(),
            payload: NodePayload::Full,
        })
    }

    /// Leaves of the viable tree, each with its weight, sorted by node.
    ///
    /// Spec vectors check these to pin the weights, not just the winner.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn viable_leaves_and_weights(
        &mut self,
    ) -> Result<Vec<(ForkChoiceNode, Gwei)>, ForkChoiceError> {
        if self.weighs_payloads() {
            return Ok(self.payload_ghost()?.viable_leaves_and_weights());
        }
        let leaves = self.ghost()?.viable_leaves_and_weights();
        Ok(leaves
            .into_iter()
            .map(|(root, weight)| {
                let node = ForkChoiceNode {
                    root,
                    payload: NodePayload::Full,
                };
                (node, weight)
            })
            .collect())
    }

    /// The node a proposer at a slot should build on: the head, or a late head's parent.
    ///
    /// The parent keeps the payload status the head built on.
    /// See `get_proposer_head` in the phase0, Fulu, and Gloas fork choice specs.
    ///
    /// # Errors
    ///
    /// Fails when the head still holds the proposer boost, or its state is missing.
    pub fn proposer_head(
        &mut self,
        head: ForkChoiceNode,
        slot: Slot,
    ) -> Result<ForkChoiceNode, ForkChoiceError> {
        if self.proposer_boost_root == head.root {
            return Err(ForkChoiceError::HeadStillBoosted(head.root));
        }
        let head_block = *self
            .blocks
            .get(&head.root)
            .ok_or(ForkChoiceError::MissingState(head.root))?;
        let parent_block = *self
            .blocks
            .get(&head_block.parent_root)
            .ok_or(ForkChoiceError::MissingState(head_block.parent_root))?;
        let parent = ForkChoiceNode {
            root: head_block.parent_root,
            payload: self
                .blocks
                .parent_payload(&head.root)
                .unwrap_or(NodePayload::Full),
        };
        let head_committees = self
            .block_states
            .get_mut(&head.root)
            .ok_or(ForkChoiceError::MissingState(head.root))?
            .committees(head_block.slot.epoch::<P>())?;
        let boundary_sensitive = !self
            .config
            .fork_at(slot.epoch::<P>())
            .fixes_proposers_ahead();
        let ghost = self.ghost()?;
        let reorg = LateHeadReorg {
            ghost,
            head,
            head_block,
            parent,
            parent_block,
            head_committees: &head_committees,
            boundary_sensitive,
        };
        Ok(reorg.parent_for(slot))
    }

    /// Whether a proposer at a slot builds on the head's full variant or its empty one.
    ///
    /// For the previous slot's head, the payload committee may veto the full variant.
    /// It does so when a majority saw the payload late or its data missing.
    /// See `should_build_on_full` in the Gloas fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the head is not in the store.
    pub fn should_build_on_full(
        &self,
        head: ForkChoiceNode,
        slot: Slot,
    ) -> Result<bool, ForkChoiceError> {
        let block = self
            .blocks
            .get(&head.root)
            .ok_or(ForkChoiceError::UnknownBlock(head.root))?;
        if block.slot + 1 != slot {
            return Ok(head.payload == NodePayload::Full);
        }
        Ok(head.payload == NodePayload::Full
            && !self.ptc.payload_timeliness(&head.root, block, false)
            && !self.ptc.payload_data_availability(&head.root, block, false))
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

    /// Records a proof-of-work block the execution layer reported.
    ///
    /// See `get_pow_block` in the Bellatrix fork choice spec.
    pub fn on_pow_block(&mut self, block: PowBlock) {
        self.pow_chain.insert(block);
    }

    /// Accepts a block: checks its place in the tree, runs it, and records its post-state.
    ///
    /// A Gloas block takes the Gloas handler; every earlier fork shares one.
    /// See `on_block` in the phase0, Bellatrix, Deneb, Fulu, and Gloas fork choice specs.
    ///
    /// # Errors
    ///
    /// Fails when the parent is unknown, the block is from the future or before finality,
    /// its data is unavailable, or the state transition rejects it.
    pub fn on_block(
        &mut self,
        signed_block: &combined::SignedBeaconBlock<P>,
        availability: DataAvailability,
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        match signed_block {
            combined::SignedBeaconBlock::Gloas(gloas_block) => self.on_gloas_block(
                signed_block,
                &gloas_block.message.body.payload_attestations,
                verification,
                payload,
            ),
            _ => self.on_payload_block(signed_block, availability, verification, payload),
        }
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
        signed_block: &combined::SignedBeaconBlock<P>,
        availability: DataAvailability,
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        self.on_block(signed_block, availability, verification, payload)?;

        // Votes inside a block skip the timing rule, since a block may carry old votes.
        let block = signed_block.message();
        for vote in block.committee_votes() {
            let _ignored = self.on_attestation(&vote, true, verification);
        }
        // Equivocation evidence removes the offenders' weight from every branch.
        for votes in block.conflicting_votes() {
            let _ignored = self.on_attester_slashing(&votes, verification);
        }
        Ok(())
    }

    /// Records a block and its post-state, skipping the timing, finality, and boost rules.
    ///
    /// This replays a chain whose blocks were already validated elsewhere.
    /// A checkpoint sync and a spec vector's history both do so.
    pub fn insert_validated_block(&mut self, block: &combined::BeaconBlock<P>, state: State<P>) {
        self.insert_validated_node(
            block.hash_tree_root(),
            BlockNode::of(block, ExecutionStatus::Valid),
            state,
        );
    }

    /// Records a block by its root and tree node, with its post-state.
    ///
    /// Like the block form, this skips the timing, finality, and boost rules.
    pub fn insert_validated_node(&mut self, root: Root, node: BlockNode, state: State<P>) {
        let justified = state.beacon().current_justified_checkpoint();
        if state.fork_name().separates_payloads() {
            self.ptc.open::<P>(root);
        }
        self.blocks.insert(root, node);
        self.block_states.insert(root, state);
        self.unrealized_justifications.insert(root, justified);
    }

    /// Records that a block's payload envelope was verified elsewhere.
    pub fn insert_validated_payload(&mut self, root: Root) {
        self.blocks.reveal_payload(root);
    }

    /// Accepts an attestation's votes.
    ///
    /// Votes from blocks skip the timing check, since a block may carry old votes.
    /// See `on_attestation` in the phase0 and Gloas fork choice specs.
    ///
    /// # Errors
    ///
    /// Fails when the vote is out of time, names unknown or inconsistent blocks, or does not verify.
    pub fn on_attestation(
        &mut self,
        vote: &CommitteeVote,
        is_from_block: bool,
        verification: Verification,
    ) -> Result<(), ForkChoiceError> {
        self.validate_on_attestation(vote, is_from_block)?;

        let data = &vote.data;
        let target = data.target;
        let config = self.config.clone();
        let state = self.checkpoint_state(target)?;
        let attesters = state
            .committees(target.epoch)?
            .attesters(
                data.slot,
                vote.committees.iter().copied(),
                vote.bits.iter().copied(),
            )
            .map_err(ForkChoiceError::InvalidAttestation)?;
        let indices: Vec<ValidatorIndex> = attesters.iter().copied().collect();
        let mut processor = BlockProcessor::new(state.any_fork(), &config, verification);
        processor
            .verify_indexed_attestation(&indices, data, &vote.signature)
            .and_then(|()| processor.finish())
            .map_err(ForkChoiceError::InvalidAttestation)?;

        // A vote that speaks about payloads is a Gloas vote, ordered by slot.
        let order = if vote.payload == PayloadClaim::Silent {
            VoteOrder::ByEpoch
        } else {
            VoteOrder::BySlot
        };
        self.votes.record::<P>(
            attesters,
            LatestMessage {
                slot: data.slot,
                root: data.beacon_block_root,
                payload_present: vote.payload == PayloadClaim::Present,
            },
            order,
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
        votes: &ConflictingVotes,
        verification: Verification,
    ) -> Result<(), ForkChoiceError> {
        let (first, second) = (&votes.first, &votes.second);
        if !first.data.is_slashable_with(&second.data) {
            return Err(ForkChoiceError::NotSlashable {
                first_target: first.data.target.epoch,
                second_target: second.data.target.epoch,
            });
        }
        let justified_root = self.checkpoints.justified().root;
        let config = self.config.clone();
        let state = self
            .block_states
            .get_mut(&justified_root)
            .ok_or(ForkChoiceError::MissingState(justified_root))?;
        let mut processor = BlockProcessor::new(state.any_fork(), &config, verification);
        processor
            .verify_indexed_attestation(&first.indices, &first.data, &first.signature)
            .and_then(|()| {
                processor.verify_indexed_attestation(
                    &second.indices,
                    &second.data,
                    &second.signature,
                )
            })
            .and_then(|()| processor.finish())
            .map_err(ForkChoiceError::InvalidAttestation)?;

        self.votes.mark_equivocating(votes.common_signers());
        Ok(())
    }

    /// Accepts a Gloas payload envelope once its block's state verifies it.
    ///
    /// The block's full variant then joins the tree, and children may build on it.
    /// See `on_execution_payload_envelope` in the Gloas fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the block is unknown, its data is unavailable, or the envelope breaks a rule.
    pub fn on_execution_payload_envelope(
        &mut self,
        signed_envelope: &SignedExecutionPayloadEnvelope<P>,
        availability: DataAvailability,
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        let root = signed_envelope.message.beacon_block_root;
        let state = self
            .block_states
            .get_mut(&root)
            .ok_or(ForkChoiceError::UnknownBlock(root))?;
        if availability == DataAvailability::Unavailable {
            return Err(ForkChoiceError::DataUnavailable(root));
        }
        // Verification changes no consensus field: only the state's caches warm up.
        state
            .verify_execution_payload_envelope(
                &self.config,
                signed_envelope,
                verification,
                &payload,
            )
            .map_err(|source| ForkChoiceError::InvalidEnvelope { root, source })?;
        self.blocks.reveal_payload(root);
        Ok(())
    }

    /// Records a payload timeliness committee member's vote on its slot's block.
    ///
    /// A vote for a block of another slot changes nothing and is accepted.
    /// Votes from blocks skip the slot and signature checks, as block processing made them.
    /// See `on_payload_attestation_message` in the Gloas fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the block is unknown or before Gloas, the voter sits outside the committee,
    /// or a vote from the wire is not current or not signed.
    pub fn on_payload_attestation_message(
        &mut self,
        message: &PayloadAttestationMessage,
        is_from_block: bool,
        verification: Verification,
    ) -> Result<(), ForkChoiceError> {
        let data = &message.data;
        let root = data.beacon_block_root;
        let current = self.current_slot();
        let gloas_epoch = self.config.gloas_fork_epoch;
        let state = self
            .block_states
            .get_mut(&root)
            .ok_or(ForkChoiceError::UnknownBlock(root))?;
        // A vote only counts for the block of its own slot.
        if data.slot != state.beacon().slot() {
            return Ok(());
        }
        let gloas_state = gloas::BeaconState::<P>::from_any(state.beacon())
            .ok_or(ForkChoiceError::NoPayloadCommittee(root))?;
        let seats: Vec<usize> = PtcWindow::of_slot(gloas_state, data.slot, gloas_epoch)
            .map_err(ForkChoiceError::InvalidPayloadVote)?
            .iter()
            .enumerate()
            .filter(|(_, member)| **member == message.validator_index)
            .map(|(seat, _)| seat)
            .collect();
        if seats.is_empty() {
            return Err(ForkChoiceError::NotInPayloadCommittee {
                validator: message.validator_index,
                slot: data.slot,
            });
        }
        if !is_from_block {
            if data.slot != current {
                return Err(ForkChoiceError::PayloadVoteNotCurrent {
                    slot: data.slot,
                    current,
                });
            }
            let domain = state
                .beacon()
                .domain(DOMAIN_PTC_ATTESTER, data.slot.epoch::<P>());
            let mut processor = BlockProcessor::new(state.any_fork(), &self.config, verification);
            processor
                .verify_signature(message.validator_index, data, domain, &message.signature)
                .and_then(|()| processor.finish())
                .map_err(ForkChoiceError::InvalidPayloadVote)?;
        }
        self.ptc
            .record(root, &seats, data.payload_present, data.blob_data_available);
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
            self.ptc.forget(root);
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
            if state.beacon().slot() < start {
                state.process_slots(&self.config, start)?;
            }
            self.checkpoint_states.insert(checkpoint, state);
        }
        self.checkpoint_states
            .get_mut(&checkpoint)
            .ok_or(ForkChoiceError::MissingState(checkpoint.root))
    }

    /// Whether the fork of the current slot weighs payloads apart from blocks.
    ///
    /// This is the one place the head rule is chosen, by the clock's fork.
    fn weighs_payloads(&self) -> bool {
        self.config
            .fork_at(self.current_epoch())
            .separates_payloads()
    }

    /// The boosted block's parent, when it is from the slot just before the boosted block.
    fn boost_parent(&self) -> Option<(Root, BlockNode)> {
        let boosted = self.blocks.get(&self.proposer_boost_root)?;
        let parent = self.blocks.get(&boosted.parent_root)?;
        (parent.slot + 1 == boosted.slot).then_some((boosted.parent_root, *parent))
    }

    /// Accepts a block that carries its payload, as every fork before Gloas does.
    ///
    /// # Algorithm
    ///
    /// 1. Check the block's place: a known parent, not from the future, after finality.
    /// 2. Check the data availability verdict, from Deneb on.
    /// 3. Run the state transition on the parent's state.
    /// 4. In Bellatrix, check a merge block builds on the terminal proof-of-work block.
    /// 5. Record the block, its timeliness, the boost, and its checkpoints.
    ///
    /// See `on_block` in the phase0, Bellatrix, Deneb, and Fulu fork choice specs.
    fn on_payload_block(
        &mut self,
        signed_block: &combined::SignedBeaconBlock<P>,
        availability: DataAvailability,
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        let block = signed_block.message();
        let root = block.hash_tree_root();
        if self.blocks.contains(&root) {
            return Ok(());
        }
        let parent_state = self.check_place(&block, root)?;
        if availability == DataAvailability::Unavailable {
            return Err(ForkChoiceError::DataUnavailable(root));
        }
        // A merge block's payload builds on the last proof-of-work block, which must be terminal.
        let is_merge_block = block.fork_name().validates_merge_block()
            && !parent_state.beacon().is_merge_transition_complete()
            && block.carries_execution_payload();

        let mut state = parent_state.clone();
        // An invalid verdict condemns optimistic ancestors too, even though this block is refused.
        if let PayloadStatus::Invalid { latest_valid_hash } = payload {
            self.blocks
                .invalidate_after(block.parent_root(), latest_valid_hash);
        }
        state
            .state_transition(&self.config, signed_block, verification, &payload)
            .map_err(|source| ForkChoiceError::InvalidBlock {
                root,
                source: Box::new(source),
            })?;
        if is_merge_block {
            self.pow_chain.validate_merge_block::<P>(
                &self.config,
                block.slot(),
                block.execution_hashes().parent_block_hash,
            )?;
        }

        let status = if payload == PayloadStatus::Valid {
            ExecutionStatus::Valid
        } else {
            ExecutionStatus::Optimistic
        };
        let deadline = self.config.attestation_due_bps;
        self.record(&block, root, status, state, deadline)?;
        if payload == PayloadStatus::Valid {
            self.blocks.mark_valid(root);
        }
        Ok(())
    }

    /// Accepts a Gloas block, which commits to a bid rather than carrying its payload.
    ///
    /// # Algorithm
    ///
    /// 1. Check the block's place, as every fork does.
    /// 2. A block building on its parent's payload needs that payload verified.
    /// 3. Run the state transition; data availability waits for the envelope.
    /// 4. Record the block, open its committee votes, and count the votes it carries.
    ///
    /// See `on_block` in the Gloas fork choice spec.
    fn on_gloas_block(
        &mut self,
        signed_block: &combined::SignedBeaconBlock<P>,
        payload_attestations: &[PayloadAttestation<P>],
        verification: Verification,
        payload: PayloadStatus,
    ) -> Result<(), ForkChoiceError> {
        let block = signed_block.message();
        let root = block.hash_tree_root();
        if self.blocks.contains(&root) {
            return Ok(());
        }
        let parent_root = block.parent_root();
        let unknown_parent = ForkChoiceError::UnknownParent {
            root,
            parent: parent_root,
        };
        let parent = self
            .blocks
            .get(&parent_root)
            .ok_or_else(|| unknown_parent.clone())?;
        let variant = self
            .blocks
            .extended_variant(&parent_root, block.execution_hashes().parent_block_hash)
            .ok_or(unknown_parent)?;
        if variant == NodePayload::Full && !parent.is_payload_verified() {
            return Err(ForkChoiceError::ParentPayloadUnverified {
                root,
                parent: parent_root,
            });
        }
        let mut state = self.check_place(&block, root)?.clone();
        state
            .state_transition(&self.config, signed_block, verification, &payload)
            .map_err(|source| ForkChoiceError::InvalidBlock {
                root,
                source: Box::new(source),
            })?;

        let deadline = self.config.attestation_due_bps_gloas;
        self.ptc.open::<P>(root);
        let slot = block.slot();
        self.record(&block, root, ExecutionStatus::Valid, state, deadline)?;
        self.notify_ptc_messages(root, slot, payload_attestations);
        Ok(())
    }

    /// Feeds the committee votes a Gloas block carries into the store, member by member.
    ///
    /// Block processing verified them, so their signatures are not checked again.
    /// A vote that does not apply, such as one on an older block, is dropped.
    /// See `notify_ptc_messages` in the Gloas fork choice spec.
    fn notify_ptc_messages(
        &mut self,
        root: Root,
        slot: Slot,
        payload_attestations: &[PayloadAttestation<P>],
    ) {
        // The genesis block carries no committee votes worth counting.
        if slot == Slot::GENESIS {
            return;
        }
        let gloas_epoch = self.config.gloas_fork_epoch;
        let mut messages = Vec::new();
        let state = self
            .block_states
            .get(&root)
            .and_then(|state| gloas::BeaconState::<P>::from_any(state.beacon()));
        if let Some(state) = state {
            for attestation in payload_attestations {
                let Ok(committee) = PtcWindow::of_slot(state, attestation.data.slot, gloas_epoch)
                else {
                    continue;
                };
                for (member, bit) in committee.iter().zip(attestation.aggregation_bits.iter()) {
                    if bit {
                        messages.push(PayloadAttestationMessage {
                            validator_index: *member,
                            data: attestation.data.clone(),
                            signature: BlsSignature::default(),
                        });
                    }
                }
            }
        }
        for message in messages {
            let _ignored = self.on_payload_attestation_message(&message, true, Verification::Skip);
        }
    }

    /// Checks a block's place in the tree, returning its parent's post-state.
    ///
    /// The parent must be known, the block's slot must have started, and it must follow finality.
    /// See `on_block` in the phase0 fork choice spec.
    fn check_place(
        &self,
        block: &combined::BeaconBlock<P>,
        root: Root,
    ) -> Result<&State<P>, ForkChoiceError> {
        let parent_root = block.parent_root();
        let parent_state =
            self.block_states
                .get(&parent_root)
                .ok_or(ForkChoiceError::UnknownParent {
                    root,
                    parent: parent_root,
                })?;
        let slot = block.slot();
        let current = self.current_slot();
        if slot > current {
            return Err(ForkChoiceError::FutureBlock { slot, current });
        }
        let finalized = self.checkpoints.finalized();
        let finalized_slot = finalized.epoch.start_slot::<P>();
        if slot <= finalized_slot {
            return Err(ForkChoiceError::BeforeFinalized {
                slot,
                finalized: finalized_slot,
            });
        }
        if self.checkpoint_block(parent_root, finalized.epoch) != Some(finalized.root) {
            return Err(ForkChoiceError::NotDescendantOfFinalized {
                root,
                finalized: finalized.root,
            });
        }
        Ok(parent_state)
    }

    /// Records an accepted block with its post-state, then its timeliness, boost, and checkpoints.
    ///
    /// The deadline is the attestation deadline of the block's fork, in basis points of a slot.
    fn record(
        &mut self,
        block: &combined::BeaconBlock<P>,
        root: Root,
        status: ExecutionStatus,
        state: State<P>,
        deadline: u64,
    ) -> Result<(), ForkChoiceError> {
        // The head before this block decides whether it may take the proposer boost.
        let head = self.head()?.root;
        let justified = state.beacon().current_justified_checkpoint();
        let finalized = state.beacon().finalized_checkpoint();

        self.blocks.insert(root, BlockNode::of(block, status));
        self.block_states.insert(root, state);
        let timeliness = Timeliness::of(
            self.clock,
            self.time_ms,
            block.slot(),
            deadline,
            self.config.payload_attestation_due_bps,
        );
        self.block_timeliness.insert(root, timeliness);
        self.update_proposer_boost_root(head, root, timeliness);
        self.checkpoints.update(justified, finalized);
        self.compute_pulled_up_tip(root)
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
    /// See `validate_on_attestation` in the phase0 and Gloas fork choice specs.
    fn validate_on_attestation(
        &self,
        vote: &CommitteeVote,
        is_from_block: bool,
    ) -> Result<(), ForkChoiceError> {
        let data = &vote.data;
        let target = data.target;

        if !is_from_block {
            let current = self.current_epoch();
            if target.epoch != current && target.epoch != current.saturating_sub(1) {
                return Err(ForkChoiceError::AttestationEpochOutOfRange {
                    target: target.epoch,
                    current,
                });
            }
        }
        if target.epoch != data.slot.epoch::<P>() {
            return Err(ForkChoiceError::AttestationTargetSlotMismatch {
                target: target.epoch,
                slot: data.slot,
            });
        }
        if !self.blocks.contains(&target.root) {
            return Err(ForkChoiceError::UnknownTarget(target.root));
        }
        let head = self
            .blocks
            .get(&data.beacon_block_root)
            .ok_or(ForkChoiceError::UnknownHead(data.beacon_block_root))?;
        if head.slot > data.slot {
            return Err(ForkChoiceError::HeadFromFuture {
                slot: data.slot,
                head_slot: head.slot,
            });
        }
        // From Gloas on, a vote may claim the payload only once it could have been seen.
        match vote.payload {
            PayloadClaim::Malformed(index) => {
                return Err(ForkChoiceError::PayloadIndexOutOfRange(index));
            }
            PayloadClaim::Present if head.slot == data.slot => {
                return Err(ForkChoiceError::SameSlotPayloadClaim(data.slot));
            }
            PayloadClaim::Present if !head.is_payload_verified() => {
                return Err(ForkChoiceError::UnverifiedPayloadClaim(
                    data.beacon_block_root,
                ));
            }
            PayloadClaim::Silent | PayloadClaim::Absent | PayloadClaim::Present => {}
        }
        // The LMD vote must agree with the FFG vote: the target is the head's checkpoint.
        if self.checkpoint_block(data.beacon_block_root, target.epoch) != Some(target.root) {
            return Err(ForkChoiceError::TargetNotHeadCheckpoint {
                target: target.root,
                head: data.beacon_block_root,
            });
        }
        // Timing: a vote only counts from the slot after it was cast.
        let current = self.current_slot();
        if current < data.slot + 1 {
            return Err(ForkChoiceError::AttestationFromFuture {
                slot: data.slot,
                current,
            });
        }
        Ok(())
    }

    /// Gives a block the proposer boost when it is timely, first, and on the head's shuffling.
    ///
    /// Proposer boost blunts the balancing attack.
    /// An adversary can no longer keep two forks tied by releasing votes at the right time.
    /// It also defeats ex ante reorgs: withheld blocks and votes cannot outweigh a timely proposal.
    ///
    /// See `update_proposer_boost_root` in the phase0 and Gloas fork choice specs.
    fn update_proposer_boost_root(&mut self, head: Root, root: Root, timeliness: Timeliness) {
        let is_first_block = self.proposer_boost_root == Root::ZERO;
        let epoch = self.current_epoch();
        let same_shuffling = self.blocks.shuffling_dependent_root::<P>(head, epoch)
            == self.blocks.shuffling_dependent_root::<P>(root, epoch);
        if timeliness.attestation && is_first_block && same_shuffling {
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
        state.process_epoch_step(&self.config, EpochStep::JustificationAndFinalization)?;
        let justified = state.beacon().current_justified_checkpoint();
        let finalized = state.beacon().finalized_checkpoint();

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
