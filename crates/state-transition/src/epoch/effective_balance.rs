//! Effective balance updates, with hysteresis.

use axiom_types::{BeaconState, Gwei, Preset};

/// The band around an effective balance inside which it does not move.
///
/// ```text
/// increment 1 ETH, hysteresis unit 0.25 ETH
///
/// lowered when balance < effective - 0.25 ETH
/// raised  when balance > effective + 1.25 ETH
/// ```
///
/// The band stops a balance hovering near a boundary from churning the effective balance.
/// See `process_effective_balance_updates` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Hysteresis {
    /// How far below the effective balance a balance may fall.
    downward: Gwei,
    /// How far above the effective balance a balance may rise.
    upward: Gwei,
}

impl Hysteresis {
    /// The band of a preset.
    pub(super) fn new<P: Preset>() -> Self {
        let hysteresis = P::EFFECTIVE_BALANCE_INCREMENT / P::HYSTERESIS_QUOTIENT;
        Self {
            downward: hysteresis * P::HYSTERESIS_DOWNWARD_MULTIPLIER,
            upward: hysteresis * P::HYSTERESIS_UPWARD_MULTIPLIER,
        }
    }

    /// Moves effective balances outside the band toward balances, in whole increments.
    pub(super) fn apply<P: Preset>(self, state: &mut BeaconState<P>) {
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        for (validator, balance) in state.validators.iter_mut().zip(state.balances.iter()) {
            let balance = *balance;
            let effective = validator.effective_balance;
            if balance.saturating_add(self.downward) < effective
                || effective.saturating_add(self.upward) < balance
            {
                let rounded = balance - Gwei(balance.0 % increment.0);
                validator.effective_balance = rounded.min(validator.max_effective_balance::<P>());
            }
        }
    }
}
