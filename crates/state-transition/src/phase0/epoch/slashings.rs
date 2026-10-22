//! The correlation penalty charged to slashed validators, before Electra.

use axiom_types::{
    Epoch, Gwei, Preset, ValidatorIndex,
    accessors::{CoreState, ForkState},
};

use crate::{ActiveBalance, CachedState, StateError};

/// The share of their stake slashed validators lose, from all stake slashed around them.
///
/// The share is the window's slashed stake times the fork's multiplier, over the total stake.
/// An isolated mistake costs little, while a coordinated attack loses everything.
///
/// ```text
/// penalty = effective / increment * adjusted / total * increment
/// adjusted = min(slashed in window * multiplier, total)
/// ```
///
/// Altair and Bellatrix raised the multiplier through the fork's constant table.
/// Electra divides in another order, so it rounds differently and has its own rule.
/// See `process_slashings` in the phase0, Altair, and Bellatrix beacon chain specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelationPenalty {
    /// Slashed stake of the window times the multiplier, at most the total.
    adjusted: Gwei,
    /// Total active balance of the ending epoch.
    total: Gwei,
    /// Withdrawable epoch of the validators charged now, halfway through their wait.
    target_withdrawable: Epoch,
}

impl CorrelationPenalty {
    /// The penalty due at a state.
    ///
    /// # Errors
    ///
    /// Fails when the slashed total overflows.
    pub fn new<S: ForkState>(
        state: &S,
        total_active_balance: ActiveBalance,
    ) -> Result<Self, StateError> {
        let total = total_active_balance.0;
        let slashed_sum = state
            .slashings()
            .iter()
            .try_fold(Gwei::ZERO, |sum, amount| sum.checked_add(*amount))
            .ok_or(StateError::Overflow {
                quantity: "slashed total",
            })?;
        let multiplier = S::FORK.proportional_slashing_multiplier::<S::Preset>();
        let scaled = slashed_sum
            .0
            .checked_mul(multiplier)
            .ok_or(StateError::Overflow {
                quantity: "slashed total times the multiplier",
            })?;
        Ok(Self {
            adjusted: Gwei(scaled).min(total),
            total,
            target_withdrawable: state.current_epoch() + S::Preset::EPOCHS_PER_SLASHINGS_VECTOR / 2,
        })
    }

    /// Charges every slashed validator halfway to its withdrawal.
    ///
    /// # Errors
    ///
    /// Fails when a penalty overflows 64 bits.
    pub fn apply<S: CoreState>(self, state: &mut CachedState<'_, S>) -> Result<(), StateError> {
        // The increment is factored out of the numerator so the product stays within 64 bits.
        let increment = S::Preset::EFFECTIVE_BALANCE_INCREMENT;
        let mut penalties = Vec::new();
        for (index, validator) in state.beacon().validators().iter().enumerate() {
            if !validator.slashed || validator.withdrawable_epoch != self.target_withdrawable {
                continue;
            }
            let numerator = (validator.effective_balance / increment)
                .checked_mul(self.adjusted.0)
                .ok_or(StateError::Overflow {
                    quantity: "correlation penalty numerator",
                })?;
            let penalty = increment * (numerator / self.total.0);
            penalties.push((ValidatorIndex::from(index), penalty));
        }
        for (index, penalty) in penalties {
            state.decrease_balance(index, penalty)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, altair, phase0::Validator};

    use super::*;
    use crate::Caches;

    #[test]
    fn the_penalty_rounds_down_to_whole_increments() {
        // Fixture state: Altair at epoch 10, one slashed validator of 32 ETH due now.
        // Minimal preset: 64 epochs per slashings vector, so the due epoch is 10 + 32 = 42.
        let mut state = altair::BeaconState::<Minimal> {
            slot: Epoch(10).start_slot::<Minimal>(),
            ..Default::default()
        };
        state
            .validators
            .push(Validator {
                slashed: true,
                effective_balance: Gwei(32_000_000_000),
                withdrawable_epoch: Epoch(42),
                ..Default::default()
            })
            .unwrap();
        state.balances.push(Gwei(32_000_000_000)).unwrap();
        // 1 ETH slashed in the window; Altair's multiplier is 2, so 2 ETH counts.
        state.slashings[3] = Gwei(1_000_000_000);

        // Total stake 100 ETH: 32 increments * 2 ETH / 100 ETH = 0.64, which rounds to 0 ETH.
        let penalty =
            CorrelationPenalty::new(&state, ActiveBalance(Gwei(100_000_000_000))).unwrap();
        let mut caches = Caches::default();
        penalty
            .apply(&mut CachedState::new(&mut state, &mut caches))
            .unwrap();
        assert_eq!(state.balances[0], Gwei(32_000_000_000));

        // Total stake 50 ETH: 32 * 2 ETH / 50 ETH = 1.28 ETH, which rounds down to 1 ETH.
        let penalty = CorrelationPenalty::new(&state, ActiveBalance(Gwei(50_000_000_000))).unwrap();
        penalty
            .apply(&mut CachedState::new(&mut state, &mut caches))
            .unwrap();
        assert_eq!(state.balances[0], Gwei(31_000_000_000));
    }
}
