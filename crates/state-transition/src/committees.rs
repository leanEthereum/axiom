//! The beacon committees of one epoch.

use std::collections::BTreeSet;

use axiom_types::{
    CommitteeIndex, Epoch, Preset, Slot, ValidatorIndex, accessors::CoreState,
    constants::DOMAIN_BEACON_ATTESTER,
};

use crate::{BlockError, SwapOrNot};

/// Every beacon committee of one epoch, computed with one shuffle.
///
/// # Overview
///
/// The active validators are shuffled once per epoch.
/// The shuffled list is then cut into contiguous committees, slot by slot.
///
/// ```text
/// shuffled:         [v7 v2 v9 | v4 v1 v8 | v3 v6 v5 | ...]
/// slot 0, index 0:   v7 v2 v9
/// slot 0, index 1:   v4 v1 v8
/// slot 1, index 0:   v3 v6 v5
/// ```
///
/// See `compute_committee` and `get_beacon_committee` in the phase0 beacon chain spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochCommittees {
    /// The epoch the committees serve.
    epoch: Epoch,
    /// Active validators in shuffled order.
    shuffled: Vec<ValidatorIndex>,
    /// Committees in each slot of the epoch.
    committees_per_slot: u64,
    /// Slots per epoch of the preset, the other factor of the committee count.
    slots_per_epoch: u64,
}

impl EpochCommittees {
    /// Committees of an epoch, as the state determines them.
    ///
    /// No fork changed how committees are formed, so the state of any fork will do.
    #[must_use]
    pub fn compute<S: CoreState + ?Sized>(state: &S, epoch: Epoch) -> Self {
        // Position j of the shuffled list holds the active validator the shuffle sends there.
        let mut shuffled = state.active_validator_indices(epoch);
        let seed = state.seed(epoch, DOMAIN_BEACON_ATTESTER);
        SwapOrNot::new(seed, S::Preset::SHUFFLE_ROUND_COUNT).shuffle(&mut shuffled);

        Self {
            epoch,
            committees_per_slot: Self::count_per_slot::<S::Preset>(shuffled.len()),
            shuffled,
            slots_per_epoch: S::Preset::SLOTS_PER_EPOCH,
        }
    }

    /// Committees per slot for an active set, between 1 and the preset maximum.
    ///
    /// See `get_committee_count_per_slot` in the phase0 beacon chain spec.
    const fn count_per_slot<P: Preset>(active_validator_count: usize) -> u64 {
        let count = active_validator_count as u64 / P::SLOTS_PER_EPOCH / P::TARGET_COMMITTEE_SIZE;
        if count < 1 {
            1
        } else if count > P::MAX_COMMITTEES_PER_SLOT {
            P::MAX_COMMITTEES_PER_SLOT
        } else {
            count
        }
    }

    /// The epoch the committees serve.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Committees in each slot.
    #[must_use]
    pub const fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// Number of active validators.
    #[must_use]
    pub const fn active_validator_count(&self) -> usize {
        self.shuffled.len()
    }

    /// The committee at a slot and index, or nothing when it does not exist.
    #[must_use]
    pub fn committee(&self, slot: Slot, index: CommitteeIndex) -> Option<&[ValidatorIndex]> {
        if slot.0 / self.slots_per_epoch != self.epoch.0 || index.0 >= self.committees_per_slot {
            return None;
        }

        // Committee k of the epoch spans [n * k / count, n * (k + 1) / count).
        let count = self.committees_per_slot * self.slots_per_epoch;
        let position = (slot.0 % self.slots_per_epoch) * self.committees_per_slot + index.0;
        let total = self.shuffled.len() as u64;
        let start = (total * position / count) as usize;
        let end = (total * (position + 1) / count) as usize;
        Some(&self.shuffled[start..end])
    }

    /// Validators that set their bit across some committees of a slot, sorted and unique.
    ///
    /// The bits run across the named committees, back to back.
    /// A phase0 attestation names one committee, an Electra attestation several.
    ///
    /// ```text
    /// committees:  1 and 3
    /// bits:        [c1 members][c3 members]
    /// ```
    ///
    /// See `get_attesting_indices` in the phase0 and Electra beacon chain specs.
    ///
    /// # Errors
    ///
    /// Fails when a committee does not exist or the bits run short.
    pub fn attesters(
        &self,
        slot: Slot,
        committee_indices: impl IntoIterator<Item = CommitteeIndex>,
        bits: impl ExactSizeIterator<Item = bool>,
    ) -> Result<BTreeSet<ValidatorIndex>, BlockError> {
        let committees = committee_indices
            .into_iter()
            .map(|index| {
                self.committee(slot, index)
                    .ok_or(BlockError::UnknownCommittee {
                        slot,
                        index,
                        committees_per_slot: self.committees_per_slot,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Bits past the committees are ignored here, as in the spec; only a short bitfield fails.
        let expected = committees.iter().map(|committee| committee.len()).sum();
        let actual = bits.len();
        if actual < expected {
            return Err(BlockError::AggregationBitsLengthMismatch { expected, actual });
        }
        let attesters = committees
            .into_iter()
            .flatten()
            .zip(bits)
            .filter_map(|(validator, bit)| bit.then_some(*validator))
            .collect();
        Ok(attesters)
    }
}
