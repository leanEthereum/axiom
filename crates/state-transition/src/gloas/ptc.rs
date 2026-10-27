//! Payload timeliness committees, which vote on whether a slot's payload arrived.

use axiom_types::{
    Bytes32, CommitteeIndex, Epoch, Preset, Root, Slot, ValidatorIndex,
    accessors::{BuilderState, ForkState},
    constants::DOMAIN_PTC_ATTESTER,
    gloas::PayloadTimelinessCommittee,
};

use crate::{BlockError, CachedState, EpochCommittees, StateError, sampling::WeightedSampler};

/// The window of payload timeliness committees: the previous, current, and next epochs.
///
/// See EIP-7732 and the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtcWindow;

impl PtcWindow {
    /// Fills the window from the state's current epoch, for a state that just gained builders.
    ///
    /// The previous epoch has no committees yet, so its slots hold zero indices.
    /// See `initialize_ptc_window` in the Gloas fork spec.
    ///
    /// # Errors
    ///
    /// Fails when an epoch of the window has no active validator.
    pub fn initialize<S: BuilderState + ForkState>(
        state: &mut CachedState<'_, S>,
    ) -> Result<(), StateError> {
        let current = state.beacon().current_epoch();
        let mut committees = Vec::with_capacity(state.beacon().ptc_window().len());
        // Phase 1: an empty previous epoch.
        for _ in 0..S::Preset::SLOTS_PER_EPOCH {
            committees.push(PayloadTimelinessCommittee::<S::Preset>::default());
        }
        // Phase 2: the current epoch and the next MIN_SEED_LOOKAHEAD epochs.
        for offset in 0..=S::Preset::MIN_SEED_LOOKAHEAD {
            committees.extend(Self::epoch_committees(state, current + offset)?);
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

    /// Drops the previous epoch's committees, and draws those of the epoch after the next.
    ///
    /// The window then covers the new previous, current, and next epochs.
    /// See `process_ptc_window` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the new epoch has no active validator.
    pub fn shift<S: BuilderState + ForkState>(
        state: &mut CachedState<'_, S>,
    ) -> Result<(), StateError> {
        let epoch = state.beacon().current_epoch() + S::Preset::MIN_SEED_LOOKAHEAD + 1;
        let committees = Self::epoch_committees(state, epoch)?;
        let window = state.beacon.ptc_window_mut();
        let shifted: Vec<PayloadTimelinessCommittee<S::Preset>> = window
            .iter()
            .skip(S::Preset::SLOTS_PER_EPOCH as usize)
            .cloned()
            .chain(committees)
            .collect();
        *window = shifted.try_into().map_err(|source| StateError::Capacity {
            list: "payload timeliness committee window",
            source,
        })?;
        Ok(())
    }

    /// The payload timeliness committee of a slot in the previous, current, or next epochs.
    ///
    /// ```text
    /// position = (epoch - current + 1) * SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH
    /// ```
    ///
    /// See `get_ptc` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the slot is before the Gloas fork or outside the window.
    pub fn of_slot<S: BuilderState + ?Sized>(
        state: &S,
        slot: Slot,
        fork_epoch: Epoch,
    ) -> Result<&PayloadTimelinessCommittee<S::Preset>, BlockError> {
        let epoch = slot.epoch::<S::Preset>();
        let current = state.current_epoch();
        let out_of_window = BlockError::PtcOutOfWindow { slot, current };
        // The window holds the epoch before the current one, and MIN_SEED_LOOKAHEAD after it.
        if epoch < fork_epoch
            || epoch + 1 < current
            || epoch > current + S::Preset::MIN_SEED_LOOKAHEAD
        {
            return Err(out_of_window);
        }
        let offset = (epoch + 1 - current) * S::Preset::SLOTS_PER_EPOCH;
        let position = offset + slot.index_in_epoch::<S::Preset>();
        state
            .ptc_window()
            .get(position as usize)
            .ok_or(out_of_window)
    }

    /// The payload timeliness committees of every slot of an epoch.
    ///
    /// Every slot draws from the epoch's beacon committees, so the epoch is shuffled once.
    /// The epoch after the next lies outside the committee cache, so its shuffle is not kept.
    ///
    /// # Errors
    ///
    /// Fails when the epoch has no active validator.
    fn epoch_committees<S: BuilderState + ForkState>(
        state: &mut CachedState<'_, S>,
        epoch: Epoch,
    ) -> Result<Vec<PayloadTimelinessCommittee<S::Preset>>, StateError> {
        let committees = state.compute_committees(epoch);
        let start = epoch.start_slot::<S::Preset>();
        (0..S::Preset::SLOTS_PER_EPOCH)
            .map(|index| Self::committee(state.beacon(), &committees, Slot(start.0 + index)))
            .collect()
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
    /// Fails when the slot's epoch has no active validator.
    pub fn committee<S: ForkState>(
        state: &S,
        committees: &EpochCommittees,
        slot: Slot,
    ) -> Result<PayloadTimelinessCommittee<S::Preset>, StateError> {
        let epoch = slot.epoch::<S::Preset>();
        let candidates: Vec<ValidatorIndex> = (0..committees.committees_per_slot())
            .filter_map(|index| committees.committee(slot, CommitteeIndex(index)))
            .flatten()
            .copied()
            .collect();
        if candidates.is_empty() {
            return Err(StateError::NoActiveValidators(epoch));
        }

        let mut preimage = [0; 40];
        preimage[..32].copy_from_slice(&state.seed(epoch, DOMAIN_PTC_ATTESTER).0);
        preimage[32..].copy_from_slice(&slot.0.to_le_bytes());
        let seed = Bytes32(Root::sha256(&preimage).0);
        let members: Vec<ValidatorIndex> = WeightedSampler::in_order(state, &candidates, seed)
            .take(S::Preset::PTC_SIZE as usize)
            .collect();
        members.try_into().map_err(|source| StateError::Capacity {
            list: "payload timeliness committee",
            source,
        })
    }
}
