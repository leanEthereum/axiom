//! The validator registry under one block's or one epoch transition's fixed totals.

use axiom_types::{ChainConfig, Epoch, ValidatorIndex};

use crate::{ActiveBalance, CachedState, Fork, StateError};

/// A state's validator registry, with the configuration and the balance its rules read.
///
/// # Overview
///
/// Exits, slashings, and deposits all change the registry.
/// Their rules read the configuration, and from Electra on the epoch's balance churn.
///
/// The churn depends on the total active balance, fixed for a block or an epoch transition.
/// This view carries that total, so no caller threads it through.
///
/// The rules themselves belong to the forks.
/// Calls go through the state's fork, so shared code always runs the right version.
#[derive(Debug)]
pub struct Registry<'a, S> {
    /// The state whose registry changes, with its caches.
    pub(crate) state: CachedState<'a, S>,
    /// The chain configuration.
    pub(crate) config: &'a ChainConfig,
    /// Total active balance of the current epoch.
    pub(crate) total_active_balance: ActiveBalance,
}

impl<'a, S: Fork> Registry<'a, S> {
    /// The registry of a state, under a fixed total active balance.
    #[must_use]
    pub const fn new(
        state: CachedState<'a, S>,
        config: &'a ChainConfig,
        total_active_balance: ActiveBalance,
    ) -> Self {
        Self {
            state,
            config,
            total_active_balance,
        }
    }

    /// The state whose registry this is, with its caches.
    pub const fn state(&mut self) -> &mut CachedState<'a, S> {
        &mut self.state
    }

    /// The chain configuration.
    #[must_use]
    pub const fn config(&self) -> &'a ChainConfig {
        self.config
    }

    /// Total active balance of the current epoch.
    #[must_use]
    pub const fn total_active_balance(&self) -> ActiveBalance {
        self.total_active_balance
    }

    /// Schedules a validator's exit, by the rules of the state's fork.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or an epoch overflows.
    pub fn initiate_exit(&mut self, index: ValidatorIndex) -> Result<(), StateError> {
        S::initiate_validator_exit(self, index)
    }

    /// Slashes a validator, by the rules of the state's fork.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    pub fn slash(
        &mut self,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
    ) -> Result<(), StateError> {
        S::slash_validator(self, slashed, whistleblower)
    }

    /// Epoch a validator exiting at an epoch can withdraw from.
    ///
    /// # Errors
    ///
    /// Fails when the epoch overflows.
    pub fn withdrawable_epoch(&self, exit_epoch: Epoch) -> Result<Epoch, StateError> {
        exit_epoch
            .checked_add(self.config.min_validator_withdrawability_delay)
            .ok_or(StateError::Overflow {
                quantity: "withdrawable epoch",
            })
    }
}
