//! Effective balance updates, with hysteresis, under one cap for every validator.

use axiom_types::{Gwei, Preset, accessors::CoreState};

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
/// Every validator shares one cap, the maximum effective balance.
/// Electra gave each validator its own cap, set by its credentials, in its own rule.
/// See `process_effective_balance_updates` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hysteresis {
    /// How far below the effective balance a balance may fall.
    downward: Gwei,
    /// How far above the effective balance a balance may rise.
    upward: Gwei,
}

impl Hysteresis {
    /// The band of a preset.
    #[must_use]
    pub fn new<P: Preset>() -> Self {
        let hysteresis = P::EFFECTIVE_BALANCE_INCREMENT / P::HYSTERESIS_QUOTIENT;
        Self {
            downward: hysteresis * P::HYSTERESIS_DOWNWARD_MULTIPLIER,
            upward: hysteresis * P::HYSTERESIS_UPWARD_MULTIPLIER,
        }
    }

    /// Moves effective balances outside the band toward balances, in whole increments.
    pub fn apply<S: CoreState + ?Sized>(self, state: &mut S) {
        let increment = S::Preset::EFFECTIVE_BALANCE_INCREMENT;
        for index in 0..state.balances().len() {
            let balance = state.balances()[index];
            let validator = &mut state.validators_mut()[index];
            let effective = validator.effective_balance;
            if balance.saturating_add(self.downward) < effective
                || effective.saturating_add(self.upward) < balance
            {
                let rounded = balance - Gwei(balance.0 % increment.0);
                validator.effective_balance = rounded.min(S::Preset::MAX_EFFECTIVE_BALANCE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Minimal, altair, constants::COMPOUNDING_WITHDRAWAL_PREFIX, phase0::Validator,
    };

    use super::*;

    #[test]
    fn every_validator_is_capped_at_the_maximum() {
        // Fixture state: two validators at 32 ETH effective, each holding 40.5 ETH.
        // The second has compounding credentials, which mean nothing before Electra.
        let mut state = altair::BeaconState::<Minimal>::default();
        for prefix in [0, COMPOUNDING_WITHDRAWAL_PREFIX] {
            let mut validator = Validator {
                effective_balance: Gwei(32_000_000_000),
                ..Default::default()
            };
            validator.withdrawal_credentials.0[0] = prefix;
            state.validators.push(validator).unwrap();
            state.balances.push(Gwei(40_500_000_000)).unwrap();
        }

        // 40.5 ETH exceeds 32 + 1.25 ETH, so both move, and both stop at the 32 ETH cap.
        Hysteresis::new::<Minimal>().apply(&mut state);

        assert_eq!(state.validators[0].effective_balance, Gwei(32_000_000_000));
        assert_eq!(state.validators[1].effective_balance, Gwei(32_000_000_000));
    }

    #[test]
    fn a_drop_inside_the_band_keeps_the_effective_balance() {
        // Fixture state: one validator at 32 ETH effective.
        let mut state = altair::BeaconState::<Minimal>::default();
        state
            .validators
            .push(Validator {
                effective_balance: Gwei(32_000_000_000),
                ..Default::default()
            })
            .unwrap();

        // 31.8 ETH is within 0.25 ETH below 32 ETH, so nothing moves.
        state.balances.push(Gwei(31_800_000_000)).unwrap();
        Hysteresis::new::<Minimal>().apply(&mut state);
        assert_eq!(state.validators[0].effective_balance, Gwei(32_000_000_000));

        // 31.7 ETH falls 0.3 ETH below, so the effective balance drops to 31 ETH.
        state.balances[0] = Gwei(31_700_000_000);
        Hysteresis::new::<Minimal>().apply(&mut state);
        assert_eq!(state.validators[0].effective_balance, Gwei(31_000_000_000));
    }
}
