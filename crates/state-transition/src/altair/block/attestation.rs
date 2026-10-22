//! Attestations under participation flags: crediting the votes a block includes.

use axiom_types::{
    Gwei, Preset, ValidatorIndex,
    accessors::ParticipationState,
    constants::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    phase0::Attestation,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, altair::flags::Inclusion};

/// A single-committee attestation, credited in participation flags by Altair's rule.
///
/// Phase0 queued the same attestation as a pending record instead.
/// Bellatrix and Capella kept this rule.
/// Deneb lifted the inclusion window, and Electra let one attestation span committees.
#[derive(Clone, Copy, Debug)]
pub struct FlaggedAttestation<'a, P: Preset>(pub &'a Attestation<P>);

impl<S: Fork + ParticipationState> Operation<S> for FlaggedAttestation<'_, S::Preset> {
    /// Records an aggregate's votes within one epoch of inclusion delay.
    ///
    /// See `process_attestation` in the Altair beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        self.apply_within(processor, Some(S::Preset::SLOTS_PER_EPOCH))
    }
}

impl<P: Preset> FlaggedAttestation<'_, P> {
    /// Records an aggregate's votes in the participation flags, and pays the proposer.
    ///
    /// The window bounds the inclusion delay, and the delay that still earns the target flag.
    /// Altair sets it to one epoch, and Deneb removes it, see EIP-7045.
    ///
    /// # Algorithm
    ///
    /// 1. Check the vote's epochs, and that it lands within the window, if any.
    /// 2. Check that the committee exists and the bits cover it exactly.
    /// 3. Decide which flags the vote earns, and check the aggregate signature.
    /// 4. Set the flags each attester did not have yet, and pay the proposer for them.
    ///
    /// See `process_attestation` in the Altair and Deneb beacon chain specs.
    ///
    /// # Errors
    ///
    /// Fails when the attestation is invalid, which invalidates the whole block.
    pub fn apply_within<S: Fork<Preset = P> + ParticipationState>(
        self,
        processor: &mut BlockProcessor<'_, S>,
        window: Option<u64>,
    ) -> Result<(), BlockError> {
        let attestation = self.0;
        let data = &attestation.data;
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
        let earliest = data
            .slot
            .checked_add(S::Preset::MIN_ATTESTATION_INCLUSION_DELAY);
        if earliest.is_none_or(|earliest| earliest > state_slot) {
            return Err(BlockError::AttestationTooEarly {
                slot: data.slot,
                state_slot,
            });
        }
        let latest = window.and_then(|window| data.slot.checked_add(window));
        if latest.is_some_and(|latest| state_slot > latest) {
            return Err(BlockError::AttestationTooLate {
                slot: data.slot,
                state_slot,
            });
        }

        // Phase 2: the committee.
        let committees = processor.state.committees(target_epoch)?;
        let committee = committees.committee(data.slot, data.index).ok_or_else(|| {
            BlockError::UnknownCommittee {
                slot: data.slot,
                index: data.index,
                committees_per_slot: committees.committees_per_slot(),
            }
        })?;
        if attestation.aggregation_bits.len() != committee.len() {
            return Err(BlockError::AggregationBitsLengthMismatch {
                expected: committee.len(),
                actual: attestation.aggregation_bits.len(),
            });
        }

        // Phase 3: flags earned, and the signature.
        // Timing: the window above already keeps the delay within Altair's target deadline.
        let delay = state_slot - data.slot;
        let flags = Inclusion::new(processor.state.beacon(), data, delay).flags(window)?;
        let attesters: Vec<ValidatorIndex> = committees
            .attesters(data.slot, [data.index], attestation.aggregation_bits.iter())?
            .into_iter()
            .collect();
        processor.verify_indexed_attestation(&attesters, data, &attestation.signature)?;

        // Phase 4: flags and the proposer reward.
        ParticipationCredit {
            flags: &flags,
            is_current: target_epoch == current_epoch,
        }
        .apply(processor, &attesters)
    }
}

/// The participation flags a vote earns, credited to its attesters.
///
/// Only flags an attester did not have yet count, so a vote included twice pays once.
/// Every fork from Altair on credits votes this way.
/// See `process_attestation` in the Altair and Electra beacon chain specs.
#[derive(Clone, Copy, Debug)]
pub struct ParticipationCredit<'a> {
    /// Indices of the flags the vote earns.
    pub flags: &'a [usize],
    /// Whether the vote targets the current epoch, rather than the previous one.
    pub is_current: bool,
}

impl ParticipationCredit<'_> {
    /// Sets each attester's missing flags, and pays the proposer for every flag set.
    ///
    /// The proposer earns 8/56 of the base reward share of every newly set flag.
    ///
    /// # Errors
    ///
    /// Fails when the proposer cannot be found or its balance overflows.
    pub fn apply<S: Fork + ParticipationState>(
        self,
        processor: &mut BlockProcessor<'_, S>,
        attesters: &[ValidatorIndex],
    ) -> Result<(), BlockError> {
        let base_reward_per_increment = processor
            .total_active_balance
            .base_reward_per_increment::<S::Preset>();
        let state = &mut *processor.state.beacon;
        // Invariant: the signature check verified every attester names a validator.
        let effective_balances: Vec<Gwei> = attesters
            .iter()
            .map(|index| state.validators()[index.as_usize()].effective_balance)
            .collect();
        let (previous, current) = state.epoch_participation_mut();
        let mut participation = if self.is_current { current } else { previous };
        let mut proposer_reward_numerator = 0_u64;
        for (index, effective_balance) in attesters.iter().zip(effective_balances) {
            let increments = effective_balance / S::Preset::EFFECTIVE_BALANCE_INCREMENT;
            let base_reward = base_reward_per_increment.0 * increments;
            let entry = &mut participation[index.as_usize()];
            for (flag, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                if self.flags.contains(&flag) && !entry.has(flag) {
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
