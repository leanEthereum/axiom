//! Payload timeliness committees, which vote on whether a slot's payload arrived.

use axiom_types::{
    Bytes32, CommitteeIndex, Preset, Root, Slot, ValidatorIndex,
    accessors::{BuilderState, CoreState},
    constants::DOMAIN_PTC_ATTESTER,
    gloas::{BeaconState, PayloadTimelinessCommittee},
};

use crate::{CachedState, StateError, sampling::WeightedSampler};

/// The window of payload timeliness committees: the previous, current, and next epochs.
///
/// See EIP-7732 and the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtcWindow;

impl PtcWindow {
    /// Fills the window from the state's current epoch, for a state that just became Gloas.
    ///
    /// The previous epoch has no committees yet, so its slots hold zero indices.
    /// See `initialize_ptc_window` in the Gloas fork spec.
    ///
    /// # Errors
    ///
    /// Fails when an epoch of the window has no active validator.
    pub fn initialize<P: Preset>(
        state: &mut CachedState<'_, BeaconState<P>>,
    ) -> Result<(), StateError> {
        let current = state.beacon().current_epoch();
        let mut committees = Vec::with_capacity(state.beacon().ptc_window().len());
        // Phase 1: an empty previous epoch.
        for _ in 0..P::SLOTS_PER_EPOCH {
            committees.push(PayloadTimelinessCommittee::<P>::default());
        }
        // Phase 2: the current epoch and the next MIN_SEED_LOOKAHEAD epochs.
        for offset in 0..=P::MIN_SEED_LOOKAHEAD {
            let start = (current + offset).start_slot::<P>();
            for index in 0..P::SLOTS_PER_EPOCH {
                committees.push(Self::committee(state, Slot(start.0 + index))?);
            }
        }
        *state.beacon.ptc_window_mut() =
            committees
                .try_into()
                .map_err(|source| StateError::Capacity {
                    list: "payload timeliness committee window",
                    source,
                })?;
        Ok(())
    }

    /// The payload timeliness committee of a slot, possibly repeating a validator.
    ///
    /// # Algorithm
    ///
    /// 1. Concatenate the slot's beacon committees, in index order.
    /// 2. Walk them in that order, accepting each member with odds set by its balance.
    /// 3. Stop at PTC_SIZE members.
    ///
    /// The committees are shuffled already, so the walk does not shuffle again.
    /// See `compute_ptc` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch is outside the cached window or has no validator.
    pub fn committee<P: Preset>(
        state: &mut CachedState<'_, BeaconState<P>>,
        slot: Slot,
    ) -> Result<PayloadTimelinessCommittee<P>, StateError> {
        let epoch = slot.epoch::<P>();
        let committees = state.committees(epoch)?;
        let candidates: Vec<ValidatorIndex> = (0..committees.committees_per_slot())
            .filter_map(|index| committees.committee(slot, CommitteeIndex(index)))
            .flatten()
            .copied()
            .collect();
        if candidates.is_empty() {
            return Err(StateError::NoActiveValidators(epoch));
        }

        let mut preimage = [0; 40];
        preimage[..32].copy_from_slice(&state.beacon().seed(epoch, DOMAIN_PTC_ATTESTER).0);
        preimage[32..].copy_from_slice(&slot.0.to_le_bytes());
        let seed = Bytes32(Root::sha256(&preimage).0);
        let members: Vec<ValidatorIndex> =
            WeightedSampler::in_order(state.beacon(), &candidates, seed)
                .take(P::PTC_SIZE as usize)
                .collect();
        members.try_into().map_err(|source| StateError::Capacity {
            list: "payload timeliness committee",
            source,
        })
    }
}
