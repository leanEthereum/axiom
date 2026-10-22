//! Attestations: crediting the votes a block includes.

use axiom_types::{
    Attestation, AttestationData, Gwei, IndexedAttestation, Preset,
    constants::{
        PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, TIMELY_HEAD_FLAG_INDEX,
        TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
    },
};

use crate::{BlockError, BlockProcessor, Operation, State, StateError};

impl<P: Preset> Operation<P> for Attestation<P> {
    /// Records an aggregate's votes in the participation flags, and pays the proposer.
    ///
    /// # Algorithm
    ///
    /// - Phase 1 checks the vote's epochs and inclusion delay.
    /// - Phase 2 checks that every selected committee has a participant and the bits fit exactly.
    /// - Phase 3 decides which flags the vote earns, and checks the aggregate signature.
    /// - Phase 4 sets the flags each attester did not have yet.
    ///
    /// The proposer earns 8/56 of the base reward share of every newly set flag.
    ///
    /// See `process_attestation` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let data = &self.data;
        let state = &processor.state.beacon;
        let current_epoch = state.current_epoch();

        // Phase 1: timing.
        let target_epoch = data.target.epoch;
        if target_epoch != state.previous_epoch() && target_epoch != current_epoch {
            return Err(BlockError::AttestationTargetEpochOutOfRange(target_epoch));
        }
        if target_epoch != data.slot.epoch::<P>() {
            return Err(BlockError::AttestationTargetSlotMismatch);
        }
        let included_after = data.slot.checked_add(P::MIN_ATTESTATION_INCLUSION_DELAY);
        if included_after.is_none_or(|earliest| earliest > state.slot) {
            return Err(BlockError::AttestationTooEarly);
        }

        // Phase 2: committees.
        if data.index.0 != 0 {
            return Err(BlockError::AttestationIndexNotZero);
        }
        let committees = processor.state.committees(target_epoch)?;
        let mut offset = 0;
        for index in self.committee_indices() {
            let committee = committees
                .committee(data.slot, index)
                .ok_or(BlockError::UnknownCommittee(index))?;
            let any_participant = (offset..offset + committee.len())
                .any(|bit| self.aggregation_bits.get(bit) == Some(true));
            if !any_participant {
                return Err(BlockError::EmptyCommittee(index));
            }
            offset += committee.len();
        }
        if self.aggregation_bits.len() != offset {
            return Err(BlockError::AggregationBitsLengthMismatch);
        }

        // Phase 3: flags earned, and the signature.
        let inclusion_delay = processor.state.beacon.slot - data.slot;
        let flags = processor.participation_flag_indices(data, inclusion_delay)?;
        let attesters = processor.state.attesting_indices(self)?;
        processor.verify_indexed_attestation(&IndexedAttestation {
            attesting_indices: attesters
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| BlockError::AggregationBitsLengthMismatch)?,
            data: data.clone(),
            signature: self.signature,
        })?;

        // Phase 4: flags and the proposer reward.
        let base_reward_per_increment =
            State::<P>::base_reward_per_increment(processor.total_active_balance);
        let state = &mut processor.state.beacon;
        let is_current = target_epoch == current_epoch;
        let mut proposer_reward_numerator = 0_u64;
        for index in attesters {
            let increments = state.validators[index.as_usize()].effective_balance
                / P::EFFECTIVE_BALANCE_INCREMENT;
            let base_reward = base_reward_per_increment.0 * increments;
            let participation = if is_current {
                &mut state.current_epoch_participation[index.as_usize()]
            } else {
                &mut state.previous_epoch_participation[index.as_usize()]
            };
            for (flag, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                if flags.contains(&flag) && !participation.has(flag) {
                    *participation = participation.with(flag);
                    proposer_reward_numerator += base_reward * weight;
                }
            }
        }

        let denominator =
            (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
        let proposer = state.beacon_proposer_index();
        processor
            .state
            .increase_balance(proposer, Gwei(proposer_reward_numerator / denominator))?;
        Ok(())
    }
}

impl<P: Preset> BlockProcessor<'_, P> {
    /// The participation flags a vote earns at an inclusion delay.
    ///
    /// | flag   | requires                         | inclusion delay       |
    /// |--------|----------------------------------|-----------------------|
    /// | source | source is the justified checkpoint | at most sqrt(slots per epoch) |
    /// | target | source and target match          | any                   |
    /// | head   | source, target, and head match   | exactly one slot      |
    ///
    /// See `get_attestation_participation_flag_indices` in the Deneb beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the source does not match, since such a vote cannot be included at all.
    pub fn participation_flag_indices(
        &self,
        data: &AttestationData,
        inclusion_delay: u64,
    ) -> Result<Vec<usize>, BlockError> {
        let state = &self.state.beacon;
        let justified = if data.target.epoch == state.current_epoch() {
            &state.current_justified_checkpoint
        } else {
            &state.previous_justified_checkpoint
        };
        if data.source != *justified {
            return Err(BlockError::AttestationSourceMismatch);
        }

        let target_root =
            state
                .block_root(data.target.epoch)
                .ok_or_else(|| StateError::BlockRootOutOfRange {
                    slot: data.target.epoch.start_slot::<P>(),
                    state_slot: state.slot,
                })?;
        let head_root =
            state
                .block_root_at_slot(data.slot)
                .ok_or(StateError::BlockRootOutOfRange {
                    slot: data.slot,
                    state_slot: state.slot,
                })?;
        let is_matching_target = data.target.root == target_root;
        let is_matching_head = is_matching_target && data.beacon_block_root == head_root;

        let mut flags = Vec::with_capacity(3);
        if inclusion_delay <= P::SLOTS_PER_EPOCH.isqrt() {
            flags.push(TIMELY_SOURCE_FLAG_INDEX);
        }
        if is_matching_target {
            flags.push(TIMELY_TARGET_FLAG_INDEX);
        }
        if is_matching_head && inclusion_delay == P::MIN_ATTESTATION_INCLUSION_DELAY {
            flags.push(TIMELY_HEAD_FLAG_INDEX);
        }
        Ok(flags)
    }
}
