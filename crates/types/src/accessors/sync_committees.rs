//! Sync committees, from Altair on.

use crate::{accessors::CoreState, altair::SyncCommittee};

/// The current and next sync committees.
///
/// See the Altair beacon chain spec.
pub trait SyncCommitteeState: CoreState {
    /// Sync committee of the current period.
    fn current_sync_committee(&self) -> &SyncCommittee<Self::Preset>;

    /// Sync committee of the current period, for the period rotation.
    fn current_sync_committee_mut(&mut self) -> &mut SyncCommittee<Self::Preset>;

    /// Sync committee of the next period.
    fn next_sync_committee(&self) -> &SyncCommittee<Self::Preset>;

    /// Sync committee of the next period, for the period rotation.
    fn next_sync_committee_mut(&mut self) -> &mut SyncCommittee<Self::Preset>;
}
