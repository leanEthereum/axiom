//! Attestations spanning several committees: crediting the votes a block includes.

use axiom_types::{
    Gwei, Preset,
    accessors::ParticipationState,
    constants::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    electra::Attestation,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, altair::flags::Inclusion};

impl<S: Fork + ParticipationState> Operation<S> for Attestation<S::Preset> {
    /// Records an aggregate's votes in the participation flags, and pays the proposer.
    ///
    /// # Algorithm
    ///
    /// 1. Check the vote's epochs and inclusion delay.
    /// 2. Check that every selected committee has a participant and the bits fit exactly.
    /// 3. Decide which flags the vote earns, and check the aggregate signature.
    /// 4. Set the flags each attester did not have yet.
    ///
    /// The proposer earns 8/56 of the base reward share of every newly set flag.
    /// Fulu kept this rule, and Gloas rewrote it with its own attestation type.
    ///
    /// See `process_attestation` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let data = &self.data;
        let state = processor.state.beacon();
        let current_epoch = state.current_epoch();
        let state_slot = state.slot();

        // Phase 1: timing.
        let target_epoch = data.target.epoch;
        if target_epoch != state.previous_epoch() && target_epoch != current_epoch {
            return Err(BlockError::AttestationTargetEpochOutOfRange {
                target: target_epoch,
                current: current_epoch,
            });
        }
        if target_epoch != data.slot.epoch::<S::Preset>() {
            return Err(BlockError::AttestationTargetSlotMismatch {
                target: target_epoch,
                slot: data.slot,
            });
        }
        let included_after = data
            .slot
            .checked_add(S::Preset::MIN_ATTESTATION_INCLUSION_DELAY);
        if included_after.is_none_or(|earliest| earliest > state_slot) {
            return Err(BlockError::AttestationTooEarly {
                slot: data.slot,
                state_slot,
            });
        }

        // Phase 2: committees.
        if data.index.0 != 0 {
            return Err(BlockError::AttestationIndexNotZero(data.index));
        }
        let committees = processor.state.committees(target_epoch)?;
        let mut offset = 0;
        for index in self.committee_indices() {
            let committee = committees.committee(data.slot, index).ok_or_else(|| {
                BlockError::UnknownCommittee {
                    slot: data.slot,
                    index,
                    committees_per_slot: committees.committees_per_slot(),
                }
            })?;
            let any_participant = (offset..offset + committee.len())
                .any(|bit| self.aggregation_bits.get(bit) == Some(true));
            if !any_participant {
                return Err(BlockError::EmptyCommittee {
                    slot: data.slot,
                    index,
                });
            }
            offset += committee.len();
        }
        if self.aggregation_bits.len() != offset {
            return Err(BlockError::AggregationBitsLengthMismatch {
                expected: offset,
                actual: self.aggregation_bits.len(),
            });
        }

        // Phase 3: flags earned, and the signature.
        // Deneb lifted Altair's deadline on target votes, so the deadline is none.
        let delay = state_slot - data.slot;
        let flags = Inclusion::new(processor.state.beacon(), data, delay).flags(None)?;
        let attesters = committees.attesters(
            data.slot,
            self.committee_indices(),
            self.aggregation_bits.iter(),
        )?;
        let attesting_indices: Vec<_> = attesters.iter().copied().collect();
        processor.verify_indexed_attestation(&attesting_indices, data, &self.signature)?;

        // Phase 4: flags and the proposer reward.
        let base_reward_per_increment = processor
            .total_active_balance
            .base_reward_per_increment::<S::Preset>();
        let is_current = target_epoch == current_epoch;
        let state = &mut *processor.state.beacon;
        let effective_balances: Vec<Gwei> = attesting_indices
            .iter()
            .map(|index| state.validators()[index.as_usize()].effective_balance)
            .collect();
        let (previous, current) = state.epoch_participation_mut();
        let participation = if is_current { current } else { previous };
        let mut proposer_reward_numerator = 0_u64;
        for (index, effective_balance) in attesting_indices.iter().zip(effective_balances) {
            let increments = effective_balance / S::Preset::EFFECTIVE_BALANCE_INCREMENT;
            let base_reward = base_reward_per_increment.0 * increments;
            // Invariant: the signature check above verified every index names a validator.
            let entry = &mut participation[index.as_usize()];
            for (flag, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                if flags.contains(&flag) && !entry.has(flag) {
                    *entry = entry.with(flag);
                    proposer_reward_numerator += base_reward * weight;
                }
            }
        }

        let denominator =
            (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
        let proposer = processor.proposer()?;
        processor
            .state
            .increase_balance(proposer, Gwei(proposer_reward_numerator / denominator))?;
        Ok(())
    }
}
