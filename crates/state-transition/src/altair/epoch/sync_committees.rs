//! Sync committees: drawing the next one, and rotating them at the end of a period.

use std::mem;

use axiom_bls::PublicKey;
use axiom_types::{
    BlsPubkey, Epoch, Preset,
    accessors::{ForkState, SyncCommitteeState},
    altair::SyncCommittee,
};

use crate::{CachedState, StateError, sampling::WeightedSampler};

/// The rotation of sync committees, seen from the ending epoch.
///
/// The next committee is drawn a full period ahead.
/// A light client can then learn it from the current committee's signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncCommitteeRotation {
    /// The epoch that is ending.
    current: Epoch,
}

impl SyncCommitteeRotation {
    /// The rotation out of an ending epoch.
    #[must_use]
    pub const fn new(current: Epoch) -> Self {
        Self { current }
    }

    /// Rotates the sync committees when a period ends.
    ///
    /// See `process_sync_committee_updates` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the next committee cannot be drawn.
    pub fn apply<S: SyncCommitteeState + ForkState>(
        self,
        state: &mut CachedState<'_, S>,
    ) -> Result<(), StateError> {
        if (self.current + 1)
            .0
            .is_multiple_of(S::Preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
        {
            let next = Self::next_committee(state)?;
            let beacon = &mut *state.beacon;
            let current = mem::replace(beacon.next_sync_committee_mut(), next);
            *beacon.current_sync_committee_mut() = current;
        }
        Ok(())
    }

    /// The next sync committee, with its aggregate key.
    ///
    /// The sampling follows the state's fork, so Electra's wider draws apply from Electra on.
    /// See `get_next_sync_committee` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the next epoch has no active validator or the keys do not aggregate.
    pub fn next_committee<S: ForkState>(
        state: &mut CachedState<'_, S>,
    ) -> Result<SyncCommittee<S::Preset>, StateError> {
        let indices = WeightedSampler::next_sync_committee(&*state.beacon)?;
        let validators = state.beacon.validators();
        let pubkeys: Vec<BlsPubkey> = indices
            .iter()
            .map(|index| validators[index.as_usize()].pubkey)
            .collect();
        let keys = indices
            .iter()
            .map(|index| state.public_key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        let aggregate = PublicKey::aggregate(&keys).map_err(StateError::InvalidSyncCommittee)?;
        Ok(SyncCommittee {
            pubkeys: pubkeys.try_into().map_err(|source| StateError::Capacity {
                list: "next sync committee",
                source,
            })?,
            aggregate_pubkey: BlsPubkey(aggregate.to_bytes()),
        })
    }
}
