//! Validator lifecycle and balance accounting.

use axiom_types::{Gwei, Preset, ValidatorIndex};

use super::EpochProcessor;
use crate::{State, StateError};

impl<P: Preset> EpochProcessor<'_, P> {
    /// Queues new validators, ejects drained ones, and activates finalized ones.
    ///
    /// Since Electra activations are not rate-limited here.
    /// The deposit queue already admits stake under the churn.
    ///
    /// See `process_registry_updates` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when an epoch overflows.
    pub fn process_registry_updates(&mut self) -> Result<(), StateError> {
        let current = self.current_epoch;
        let activation_epoch = State::<P>::activation_exit_epoch(current);
        let finalized = self.state.beacon.finalized_checkpoint.epoch;
        let ejection_balance = self.config.ejection_balance;

        for index in 0..self.state.beacon.validators.len() {
            let validator = &self.state.beacon.validators[index];
            if validator.is_eligible_for_activation_queue::<P>() {
                self.state.beacon.validators[index].activation_eligibility_epoch = current + 1;
            } else if validator.is_active_at(current)
                && validator.effective_balance <= ejection_balance
            {
                let total_active_balance = self.total_active_balance;
                self.state.initiate_validator_exit(
                    self.config,
                    ValidatorIndex::from(index),
                    total_active_balance,
                )?;
            } else if validator.is_eligible_for_activation(finalized) {
                self.state.beacon.validators[index].activation_epoch = activation_epoch;
            }
        }
        Ok(())
    }

    /// Charges slashed validators the correlation penalty, halfway to their withdrawal.
    ///
    /// The penalty scales with all stake slashed in the surrounding window, times three.
    /// An isolated mistake costs little, while a coordinated one-third attack loses everything.
    ///
    /// See `process_slashings` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a validator vanished, which cannot happen.
    pub fn process_slashings(&mut self) -> Result<(), StateError> {
        let total = self.total_active_balance;
        let state = &self.state.beacon;
        let slashed_sum = state
            .slashings
            .iter()
            .try_fold(Gwei::ZERO, |sum, amount| sum.checked_add(*amount))
            .ok_or(StateError::Overflow)?;
        let adjusted = Gwei(
            slashed_sum
                .0
                .saturating_mul(P::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX),
        )
        .min(total);
        // The increment is factored out of the total so the product stays within 64 bits.
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        let penalty_per_increment = adjusted / (total / increment);
        let target_withdrawable = self.current_epoch + P::EPOCHS_PER_SLASHINGS_VECTOR / 2;

        let penalties: Vec<(ValidatorIndex, Gwei)> = state
            .validators
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.slashed && validator.withdrawable_epoch == target_withdrawable
            })
            .map(|(index, validator)| {
                let penalty = penalty_per_increment * (validator.effective_balance / increment);
                (ValidatorIndex::from(index), penalty)
            })
            .collect();
        for (index, penalty) in penalties {
            self.state.decrease_balance(index, penalty)?;
        }
        Ok(())
    }

    /// Moves effective balances toward balances, in whole increments, with hysteresis.
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
    pub fn process_effective_balance_updates(&mut self) {
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        let hysteresis = increment / P::HYSTERESIS_QUOTIENT;
        let downward = hysteresis * P::HYSTERESIS_DOWNWARD_MULTIPLIER;
        let upward = hysteresis * P::HYSTERESIS_UPWARD_MULTIPLIER;

        let state = &mut self.state.beacon;
        for (validator, balance) in state.validators.iter_mut().zip(state.balances.iter()) {
            let balance = *balance;
            let effective = validator.effective_balance;
            if balance.saturating_add(downward) < effective
                || effective.saturating_add(upward) < balance
            {
                let rounded = balance - Gwei(balance.0 % increment.0);
                validator.effective_balance = rounded.min(validator.max_effective_balance::<P>());
            }
        }
    }
}
