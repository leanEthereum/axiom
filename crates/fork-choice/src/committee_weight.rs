//! One slot's committee weight, the unit of proposer boost and reorg thresholds.

use axiom_types::{Gwei, Preset, accessors::CoreState, combined::BeaconState};

/// The stake of one slot's committees in a state.
///
/// Slashed validators do not count.
/// See `calculate_committee_fraction` in the phase0 fork choice spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CommitteeWeight(Gwei);

impl CommitteeWeight {
    /// The committee weight of a state's current epoch.
    pub(crate) fn of<P: Preset>(state: &BeaconState<P>) -> Self {
        let epoch = state.current_epoch();
        let total: Gwei = state
            .validators()
            .iter()
            .filter(|validator| validator.is_active_at(epoch) && !validator.slashed)
            .map(|validator| validator.effective_balance)
            .sum();
        Self::from_total::<P>(total)
    }

    /// The committee weight of a total unslashed active balance.
    pub(crate) fn from_total<P: Preset>(total: Gwei) -> Self {
        Self(total.max(P::EFFECTIVE_BALANCE_INCREMENT) / P::SLOTS_PER_EPOCH)
    }

    /// A share of the weight, as a percentage.
    pub(crate) fn percent(self, percent: u64) -> Gwei {
        self.0 * percent / 100
    }
}
