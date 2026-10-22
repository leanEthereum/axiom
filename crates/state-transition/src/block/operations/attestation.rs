//! Attestations: crediting the votes a block includes.

use axiom_types::{
    Attestation, AttestationData, BeaconState, Gwei, IndexedAttestation, Preset,
    constants::{
        PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, TIMELY_HEAD_FLAG_INDEX,
        TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
    },
};

use crate::{BlockError, BlockProcessor, Operation, StateError};

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
            return Err(BlockError::AttestationTargetEpochOutOfRange {
                target: target_epoch,
                current: current_epoch,
            });
        }
        if target_epoch != data.slot.epoch::<P>() {
            return Err(BlockError::AttestationTargetSlotMismatch {
                target: target_epoch,
                slot: data.slot,
            });
        }
        let included_after = data.slot.checked_add(P::MIN_ATTESTATION_INCLUSION_DELAY);
        if included_after.is_none_or(|earliest| earliest > state.slot) {
            return Err(BlockError::AttestationTooEarly {
                slot: data.slot,
                state_slot: state.slot,
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
        let flags = Inclusion::new(&processor.state.beacon, data).flags()?;
        let attesters = processor.state.attesting_indices(self)?;
        processor.verify_indexed_attestation(&IndexedAttestation {
            attesting_indices: attesters
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|source| StateError::Capacity {
                    list: "attesting indices",
                    source,
                })?,
            data: data.clone(),
            signature: self.signature,
        })?;

        // Phase 4: flags and the proposer reward.
        let base_reward_per_increment = processor
            .total_active_balance
            .base_reward_per_increment::<P>();
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

/// A vote included in a block, with the state that judges it.
#[derive(Debug)]
struct Inclusion<'a, P: Preset> {
    /// The state at the including block.
    state: &'a BeaconState<P>,
    /// The vote.
    data: &'a AttestationData,
    /// Slots between the vote and the including block.
    delay: u64,
}

impl<'a, P: Preset> Inclusion<'a, P> {
    /// A vote included at a state's slot.
    fn new(state: &'a BeaconState<P>, data: &'a AttestationData) -> Self {
        Self {
            state,
            data,
            delay: state.slot - data.slot,
        }
    }

    /// The participation flags the vote earns at its inclusion delay.
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
    fn flags(&self) -> Result<Vec<usize>, BlockError> {
        let state = self.state;
        let data = self.data;
        let inclusion_delay = self.delay;
        let justified = if data.target.epoch == state.current_epoch() {
            &state.current_justified_checkpoint
        } else {
            &state.previous_justified_checkpoint
        };
        if data.source != *justified {
            return Err(BlockError::AttestationSourceMismatch {
                claimed: data.source,
                justified: *justified,
            });
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
