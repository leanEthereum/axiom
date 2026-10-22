//! The weight each validator's vote carries, read once from the justified checkpoint state.

use axiom_types::{Gwei, Preset, ValidatorIndex, accessors::CoreState, combined::BeaconState};

use crate::committee_weight::CommitteeWeight;

/// Every validator's voting weight in one balance source, and that source's committee weight.
///
/// Active, unslashed validators weigh their effective balance; every other one weighs nothing.
/// See `get_attestation_score` in the phase0 fork choice spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VoteWeights {
    /// Weight of each validator of the source's registry, by index.
    weights: Vec<Gwei>,
    /// One slot's committee weight in the source.
    committee: CommitteeWeight,
}

impl VoteWeights {
    /// The weights of a balance source's validator set.
    pub(crate) fn of<P: Preset>(state: &BeaconState<P>) -> Self {
        let epoch = state.current_epoch();
        let weights: Vec<Gwei> = state
            .validators()
            .iter()
            .map(|validator| {
                if validator.is_active_at(epoch) && !validator.slashed {
                    validator.effective_balance
                } else {
                    Gwei::ZERO
                }
            })
            .collect();
        let total = weights.iter().copied().sum();
        Self {
            weights,
            committee: CommitteeWeight::from_total::<P>(total),
        }
    }

    /// Weight of a validator's vote, nothing for one outside the registry.
    pub(crate) fn of_validator(&self, validator: ValidatorIndex) -> Gwei {
        self.weights
            .get(validator.as_usize())
            .copied()
            .unwrap_or_default()
    }

    /// One slot's committee weight in the source.
    pub(crate) const fn committee(&self) -> CommitteeWeight {
        self.committee
    }
}
