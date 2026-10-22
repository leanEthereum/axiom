//! The store's event handlers: blocks, attestations, and attester slashings.

use std::collections::HashSet;

use axiom_ssz::Ssz;
use axiom_state_transition::{
    BlockProcessor, EpochProcessor, EpochStep, State, StateError, Verification,
};
use axiom_types::{
    Attestation, AttesterSlashing, BeaconBlock, Epoch, Hash32, IndexedAttestation, Preset, Root,
    SignedBeaconBlock, Slot,
};

use crate::{BlockNode, ExecutionStatus, ForkChoiceError, LatestMessage, PayloadStatus, Store};

/// Whether a block's blobs were shown to be available.
///
/// The check samples data column sidecars and verifies their proofs.
/// It needs the network and KZG, so the caller performs it and passes the verdict in.
///
/// See `is_data_available` in the Fulu fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataAvailability {
    /// Every sampled column arrived and verified.
    Available,
    /// Some sampled column is missing or invalid.
    Unavailable,
}

impl<P: Preset> Store<P> {
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
        let finalized_slot = self.finalized_checkpoint.epoch.start_slot::<P>();
        if block.slot <= finalized_slot {
            return Err(ForkChoiceError::BeforeFinalized(block.slot));
        }
        if self.checkpoint_block(block.parent_root, self.finalized_checkpoint.epoch)
            != Some(self.finalized_checkpoint.root)
        {
            return Err(ForkChoiceError::NotDescendantOfFinalized);
        }
        if availability == DataAvailability::Unavailable {
            return Err(ForkChoiceError::DataUnavailable);
        }

        let mut state = parent_state.clone();
        // An invalid verdict condemns optimistic ancestors too, even though this block is refused.
        if let PayloadStatus::Invalid { latest_valid_hash } = payload {
            self.invalidate_after(block.parent_root, latest_valid_hash);
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
        self.update_checkpoints(justified, finalized);
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
    /// This replays a chain whose blocks were already validated elsewhere, such as a
    /// checkpoint sync or a spec vector's history.
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

    /// Invalidates the optimistic blocks an invalid payload condemns.
    ///
    /// The engine names the latest valid ancestor of the invalid payload.
    /// Every block after it on the invalid payload's chain is invalid too.
    ///
    /// | latest valid hash | first invalid block                                    |
    /// |-------------------|--------------------------------------------------------|
    /// | a known hash      | the child of that block on the chain                    |
    /// | unknown or absent | the block whose payload was judged, not yet in the store |
    ///
    /// See "How to apply latestValidHash" in the Bellatrix optimistic sync spec.
    pub fn invalidate_after(&mut self, parent: Root, latest_valid_hash: Option<Hash32>) {
        let Some(latest_valid_hash) = latest_valid_hash else {
            return;
        };
        let mut child: Option<Root> = None;
        let mut current = parent;
        while let Some(node) = self.blocks.get(&current) {
            if node.execution_block_hash == latest_valid_hash {
                if let Some(first_invalid) = child {
                    self.blocks.mark_invalid(first_invalid);
                }
                return;
            }
            child = Some(current);
            current = node.parent_root;
        }
    }

    /// Records that the engine validated a block's payload, after an optimistic import.
    ///
    /// A valid payload implies valid ancestors, so they turn valid too.
    /// See the Bellatrix optimistic sync spec.
    pub fn on_valid_payload(&mut self, root: Root) {
        self.blocks.mark_valid(root);
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
        let justified_root = self.justified_checkpoint.root;
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

        let second: HashSet<_> = slashing.attestation_2.attesting_indices.iter().collect();
        let both = slashing
            .attestation_1
            .attesting_indices
            .iter()
            .filter(|index| second.contains(index))
            .copied();
        self.votes.mark_equivocating(both);
        Ok(())
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
        let deadline = self.slot_component_ms(self.config.attestation_due_bps);
        let timely = self.current_slot() == slot && self.time_into_slot_ms() < deadline;
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
        let same_shuffling = self.shuffling_dependent_root(head, epoch)
            == self.shuffling_dependent_root(root, epoch);
        if is_timely && is_first_block && same_shuffling {
            self.proposer_boost_root = root;
        }
    }

    /// The block whose randomness fixed an epoch's proposer shuffling, on a block's chain.
    ///
    /// See `get_shuffling_dependent_root` in the phase0 fork choice spec.
    fn shuffling_dependent_root(&self, root: Root, epoch: Epoch) -> Option<Root> {
        let lookahead_start = epoch
            .saturating_sub(P::MIN_SEED_LOOKAHEAD)
            .start_slot::<P>();
        self.blocks
            .ancestor(root, lookahead_start.saturating_sub(1))
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
        self.update_unrealized_checkpoints(justified, finalized);

        let block_epoch = self
            .blocks
            .get(&root)
            .map_or(Epoch::GENESIS, |node| node.slot.epoch::<P>());
        if block_epoch < self.current_epoch() {
            self.update_checkpoints(justified, finalized);
        }
        Ok(())
    }
}
