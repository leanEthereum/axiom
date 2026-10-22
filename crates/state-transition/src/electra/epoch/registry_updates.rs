//! Registry updates: queueing, ejecting, and activating validators.

use axiom_types::{ChainConfig, Epoch, Gwei, ValidatorIndex, accessors::CoreState};

use crate::{Fork, Registry, StateError};

/// The epochs and threshold one round of registry updates decides by.
///
/// Since Electra activations are not rate-limited here.
/// The deposit queue already admits stake under the churn.
///
/// See `process_registry_updates` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryUpdates {
    /// The epoch that is ending.
    current: Epoch,
    /// The epoch validators activated now become active.
    activation_epoch: Epoch,
    /// The finalized epoch, which activation eligibility must precede.
    finalized: Epoch,
    /// Effective balance at or below which an active validator is ejected.
    ejection_balance: Gwei,
}

impl RegistryUpdates {
    /// The updates due at a state.
    #[must_use]
    pub fn new<S: CoreState + ?Sized>(state: &S, config: &ChainConfig) -> Self {
        let current = state.current_epoch();
        Self {
            current,
            activation_epoch: current.activation_exit_epoch::<S::Preset>(),
            finalized: state.finalized_checkpoint().epoch,
            ejection_balance: config.ejection_balance,
        }
    }

    /// Queues new validators, ejects drained ones, and activates finalized ones.
    ///
    /// # Errors
    ///
    /// Fails when an epoch overflows.
    pub fn apply<S: Fork>(self, registry: &mut Registry<'_, S>) -> Result<(), StateError> {
        let count = registry.state.beacon().validators().len();
        for index in 0..count {
            let validator = &mut registry.state.beacon.validators_mut()[index];
            if validator.is_eligible_for_activation_queue::<S::Preset>() {
                validator.activation_eligibility_epoch = self.current + 1;
            } else if validator.is_active_at(self.current)
                && validator.effective_balance <= self.ejection_balance
            {
                registry.initiate_exit(ValidatorIndex::from(index))?;
            } else if validator.is_eligible_for_activation(self.finalized) {
                validator.activation_epoch = self.activation_epoch;
            }
        }
        Ok(())
    }
}
