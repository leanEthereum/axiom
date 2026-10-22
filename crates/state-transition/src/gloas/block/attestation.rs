//! Attestations of Gloas: votes that also say whether the head's payload arrived.

use axiom_types::{
    Gwei, Preset, Slot, ValidatorIndex,
    accessors::{BuilderState, CoreState, ParticipationState},
    constants::TIMELY_HEAD_FLAG_INDEX,
    gloas::Attestation,
    phase0::AttestationData,
};

use crate::{
    BlockError, BlockProcessor, EpochCommittees, Fork, Operation, StateError,
    altair::{block::ParticipationCredit, flags::Inclusion},
};

/// An attestation included in a block, with the slot of that block's parent.
///
/// # Overview
///
/// Gloas reuses the attestation's committee index field, which Electra retired.
/// It now carries the payload availability the attester saw, 0 for empty and 1 for full.
///
/// A head vote counts only when that signal matches the chain.
/// The chain records availability by slot, and the parent is where the attested head can be.
/// So the signal is checked at the parent's slot, even when the attested slot was skipped.
///
/// A vote for the block of its own slot cannot have seen a payload yet.
/// Such same-slot votes instead weigh in on the builder payment of that slot.
///
/// See EIP-7732 and `process_attestation` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct IncludedAttestation<'a, P: Preset> {
    /// The attestation.
    attestation: &'a Attestation<P>,
    /// Slot of the parent of the including block.
    parent_slot: Slot,
}

impl<'a, P: Preset> IncludedAttestation<'a, P> {
    /// An attestation in a block whose parent is at a slot.
    #[must_use]
    pub const fn new(attestation: &'a Attestation<P>, parent_slot: Slot) -> Self {
        Self {
            attestation,
            parent_slot,
        }
    }

    /// Whether a vote is for the block proposed at its own slot.
    ///
    /// A vote at slot 0 counts as same-slot, since genesis has no earlier block.
    /// See `is_attestation_same_slot` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the vote's slot is outside the block roots the state keeps.
    pub fn is_same_slot<S: CoreState<Preset = P> + ?Sized>(
        state: &S,
        data: &AttestationData,
    ) -> Result<bool, StateError> {
        if data.slot.0 == 0 {
            return Ok(true);
        }
        let root_at = |slot: Slot| {
            state
                .block_root_at_slot(slot)
                .ok_or_else(|| StateError::BlockRootOutOfRange {
                    slot,
                    state_slot: state.slot(),
                })
        };
        let slot_root = root_at(data.slot)?;
        let previous_root = root_at(data.slot - 1)?;
        Ok(data.beacon_block_root == slot_root && data.beacon_block_root != previous_root)
    }

    /// Checks the vote's epochs, its inclusion delay, and its payload signal of 0 or 1.
    fn check_timing<S: CoreState<Preset = P>>(&self, state: &S) -> Result<(), BlockError> {
        let data = &self.attestation.data;
        let current_epoch = state.current_epoch();
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
        if included_after.is_none_or(|earliest| earliest > state.slot()) {
            return Err(BlockError::AttestationTooEarly {
                slot: data.slot,
                state_slot: state.slot(),
            });
        }
        if data.index.0 >= 2 {
            return Err(BlockError::AttestationPayloadIndexOutOfRange(data.index));
        }
        Ok(())
    }

    /// Checks that every selected committee has a participant, and the bits fit them exactly.
    fn check_committees(&self, committees: &EpochCommittees) -> Result<(), BlockError> {
        let attestation = self.attestation;
        let slot = attestation.data.slot;
        let mut offset = 0;
        for index in attestation.committee_indices() {
            let committee =
                committees
                    .committee(slot, index)
                    .ok_or_else(|| BlockError::UnknownCommittee {
                        slot,
                        index,
                        committees_per_slot: committees.committees_per_slot(),
                    })?;
            let any_participant = (offset..offset + committee.len())
                .any(|bit| attestation.aggregation_bits.get(bit) == Some(true));
            if !any_participant {
                return Err(BlockError::EmptyCommittee { slot, index });
            }
            offset += committee.len();
        }
        if attestation.aggregation_bits.len() != offset {
            return Err(BlockError::AggregationBitsLengthMismatch {
                expected: offset,
                actual: attestation.aggregation_bits.len(),
            });
        }
        Ok(())
    }

    /// Adds the stake of first-time attesters to the attested slot's builder payment.
    ///
    /// Called only for a same-slot vote that earns some flag.
    /// An attester with no flag yet this epoch then sets a new one.
    /// Each attester thus weighs in once per epoch, on its first vote only.
    /// A payment with nothing owed gathers no weight.
    ///
    /// The entry is the attested slot's, in the target epoch's half of the payments.
    ///
    /// # Errors
    ///
    /// Fails when the weight overflows 64 bits.
    fn weigh_payment<S: ParticipationState<Preset = P> + BuilderState<Preset = P>>(
        &self,
        state: &mut S,
        attesters: &[ValidatorIndex],
        is_current: bool,
    ) -> Result<(), StateError> {
        let half = if is_current { P::SLOTS_PER_EPOCH } else { 0 };
        let entry = (half + self.attestation.data.slot.index_in_epoch::<P>()) as usize;
        if state.builder_pending_payments()[entry].withdrawal.amount == Gwei::ZERO {
            return Ok(());
        }
        let participation = if is_current {
            state.current_epoch_participation()
        } else {
            state.previous_epoch_participation()
        };
        // Invariant: the signature check verified every attester names a validator.
        let added: Gwei = attesters
            .iter()
            .filter(|index| participation[index.as_usize()].0 == 0)
            .map(|index| state.validators()[index.as_usize()].effective_balance)
            .sum();
        let payment = &mut state.builder_pending_payments_mut()[entry];
        payment.weight = payment
            .weight
            .checked_add(added)
            .ok_or(StateError::Overflow {
                quantity: "builder payment weight",
            })?;
        Ok(())
    }

    /// The participation flags the vote earns, with the payload signal checked for the head flag.
    ///
    /// See `get_attestation_participation_flag_indices` in the Gloas beacon chain spec.
    fn flags<S: BuilderState<Preset = P>>(
        &self,
        state: &S,
        delay: u64,
        same_slot: bool,
    ) -> Result<Vec<usize>, BlockError> {
        let data = &self.attestation.data;
        let payload_matches = if same_slot {
            if data.index.0 != 0 {
                return Err(BlockError::SameSlotPayloadSignal {
                    slot: data.slot,
                    index: data.index,
                });
            }
            true
        } else {
            let position = (self.parent_slot.0 % P::SLOTS_PER_HISTORICAL_ROOT) as usize;
            let available = state
                .execution_payload_availability()
                .get(position)
                .unwrap_or_default();
            data.index.0 == u64::from(available)
        };
        // Deneb lifted Altair's deadline on target votes, so the deadline is none.
        let mut flags = Inclusion::new(state, data, delay).flags(None)?;
        if !payload_matches {
            flags.retain(|flag| *flag != TIMELY_HEAD_FLAG_INDEX);
        }
        Ok(flags)
    }
}

impl<S> Operation<S> for IncludedAttestation<'_, S::Preset>
where
    S: Fork + ParticipationState + BuilderState,
{
    /// Records an aggregate's votes in the participation flags, pays the proposer, and weighs payments.
    ///
    /// # Algorithm
    ///
    /// 1. Check the vote's epochs and inclusion delay, and its payload signal of 0 or 1.
    /// 2. Check that every selected committee has a participant and the bits fit exactly.
    /// 3. Decide which flags the vote earns, and check the aggregate signature.
    /// 4. A same-slot attester voting for the first time this epoch adds its stake to the payment.
    /// 5. Set the flags each attester did not have yet, and pay the proposer for them.
    ///
    /// The payment reads participation before the flags change, so it sees first votes.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let attestation = self.attestation;
        let data = &attestation.data;
        let state = processor.state.beacon();
        let current_epoch = state.current_epoch();
        let state_slot = state.slot();
        let target_epoch = data.target.epoch;

        // Phase 1: timing and the payload signal.
        self.check_timing(state)?;

        // Phase 2: committees.
        let committees = processor.state.committees(target_epoch)?;
        self.check_committees(&committees)?;

        // Phase 3: flags earned, and the signature.
        let state = processor.state.beacon();
        let same_slot = Self::is_same_slot(state, data)?;
        let flags = self.flags(state, state_slot - data.slot, same_slot)?;
        let attesters = committees.attesters(
            data.slot,
            attestation.committee_indices(),
            attestation.aggregation_bits.iter(),
        )?;
        let attesting_indices: Vec<_> = attesters.iter().copied().collect();
        processor.verify_indexed_attestation(&attesting_indices, data, &attestation.signature)?;

        // Phase 4: the builder payment's weight, read before the flags change.
        let is_current = target_epoch == current_epoch;
        if same_slot && !flags.is_empty() {
            self.weigh_payment(&mut *processor.state.beacon, &attesting_indices, is_current)?;
        }

        // Phase 5: flags and the proposer reward, by Altair's rule.
        ParticipationCredit {
            flags: &flags,
            is_current,
        }
        .apply(processor, &attesting_indices)
    }
}
