//! Phase0 attestations: votes kept whole in the state until their epoch is scored.

use axiom_types::{
    Preset, Slot,
    accessors::CoreState,
    phase0::{Attestation, BeaconState, PendingAttestation},
};

use crate::{BlockError, BlockProcessor, Operation, StateError};

/// An attestation included in a phase0 block, about to be recorded as pending.
///
/// Phase0 scores votes only at the end of their epoch, from the pending records.
/// Altair rewrote this rule to set participation flags at inclusion instead.
#[derive(Clone, Copy, Debug)]
pub struct AttestationRecord<'a, P: Preset>(pub &'a Attestation<P>);

impl<P: Preset> Operation<BeaconState<P>> for AttestationRecord<'_, P> {
    /// Checks a committee's vote and records it with its inclusion delay and proposer.
    ///
    /// # Algorithm
    ///
    /// 1. Check the target epoch, and that the vote is between one slot and one epoch old.
    /// 2. Check the committee exists and the bits cover exactly its members.
    /// 3. Check the source is the justified checkpoint of the target's epoch, and record the vote.
    /// 4. Check the aggregate signature of the committee members that set their bit.
    ///
    /// See `process_attestation` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, BeaconState<P>>) -> Result<(), BlockError> {
        let attestation = self.0;
        let data = &attestation.data;
        let state = processor.state.beacon();
        let current_epoch = state.current_epoch();
        let state_slot = state.slot;

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
        let earliest = data.slot.checked_add(P::MIN_ATTESTATION_INCLUSION_DELAY);
        if earliest.is_none_or(|earliest| earliest > state_slot) {
            return Err(BlockError::AttestationTooEarly {
                slot: data.slot,
                state_slot,
            });
        }
        // The slot is at most the state's slot here, so adding an epoch cannot overflow in practice.
        if data.slot.0.saturating_add(P::SLOTS_PER_EPOCH) < state_slot.0 {
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

        // Phase 3: the record, in the list of the target's epoch.
        let pending = PendingAttestation {
            aggregation_bits: attestation.aggregation_bits.clone(),
            data: data.clone(),
            inclusion_delay: Slot(state_slot - data.slot),
            proposer_index: processor.proposer()?,
        };
        let state = &mut *processor.state.beacon;
        let (justified, records) = if target_epoch == current_epoch {
            (
                state.current_justified_checkpoint,
                &mut state.current_epoch_attestations,
            )
        } else {
            (
                state.previous_justified_checkpoint,
                &mut state.previous_epoch_attestations,
            )
        };
        if data.source != justified {
            return Err(BlockError::AttestationSourceMismatch {
                claimed: data.source,
                justified,
            });
        }
        records
            .push(pending)
            .map_err(|source| StateError::Capacity {
                list: "pending attestations",
                source,
            })?;

        // Phase 4: the signature of the members that set their bit.
        let attesters: Vec<_> = committees
            .attesters(data.slot, [data.index], attestation.aggregation_bits.iter())?
            .into_iter()
            .collect();
        processor.verify_indexed_attestation(&attesters, data, &attestation.signature)
    }
}
