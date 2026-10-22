//! The correlation penalty charged to slashed validators.

use axiom_types::{
    Epoch, Gwei, Preset, ValidatorIndex,
    accessors::{CoreState, ForkState},
};

use crate::{ActiveBalance, CachedState, StateError};

/// The penalty rate of one epoch, from all stake slashed in the surrounding window.
///
/// The penalty scales with that stake, times the fork's multiplier.
/// An isolated mistake costs little, while a coordinated one-third attack loses everything.
///
/// Electra computes the rate per increment first, so it rounds differently than before.
/// See `process_slashings` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelationPenalty {
    /// Penalty per increment of effective balance.
    per_increment: Gwei,
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
        let adjusted = Gwei(slashed_sum.0.saturating_mul(multiplier)).min(total);
        // The increment is factored out of the total so the product stays within 64 bits.
        let increment = S::Preset::EFFECTIVE_BALANCE_INCREMENT;
        Ok(Self {
            per_increment: adjusted / (total / increment),
            target_withdrawable: state.current_epoch() + S::Preset::EPOCHS_PER_SLASHINGS_VECTOR / 2,
        })
    }

    /// Charges every slashed validator halfway to its withdrawal.
    ///
    /// # Errors
    ///
    /// Fails when a validator vanished, which cannot happen.
    pub fn apply<S: CoreState>(self, state: &mut CachedState<'_, S>) -> Result<(), StateError> {
        let increment = S::Preset::EFFECTIVE_BALANCE_INCREMENT;
        let penalties: Vec<(ValidatorIndex, Gwei)> = state
            .beacon()
            .validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.slashed && validator.withdrawable_epoch == self.target_withdrawable
            })
            .map(|(index, validator)| {
                let penalty = self.per_increment * (validator.effective_balance / increment);
                (ValidatorIndex::from(index), penalty)
            })
            .collect();
        for (index, penalty) in penalties {
            state.decrease_balance(index, penalty)?;
        }
        Ok(())
    }
}
