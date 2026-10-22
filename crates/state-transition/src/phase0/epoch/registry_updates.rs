//! Registry updates: queueing, ejecting, and activating validators under a churn limit.

use axiom_types::{ChainConfig, Epoch, Gwei, Preset, ValidatorIndex, accessors::CoreState};

use crate::{Fork, Registry, StateError, phase0::ExitQueue};

/// The epochs, threshold, and churn one round of registry updates decides by.
///
/// Activations leave a queue ordered by eligibility, at most a churn of validators per epoch.
/// Altair, Bellatrix, and Capella kept this rule.
/// Deneb capped the activation churn, and Electra replaced the queue with a balance churn.
///
/// See `process_registry_updates` in the phase0 beacon chain spec.
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
    /// Validators the queue activates this epoch at most.
    churn_limit: u64,
}

impl RegistryUpdates {
    /// The updates due at a state.
    ///
    /// Ejections schedule exits in a later epoch, so they leave the churn unchanged.
    #[must_use]
    pub fn new<S: CoreState + ?Sized>(state: &S, config: &ChainConfig) -> Self {
        let current = state.current_epoch();
        Self {
            current,
            activation_epoch: current.activation_exit_epoch::<S::Preset>(),
            finalized: state.finalized_checkpoint().epoch,
            ejection_balance: config.ejection_balance,
            churn_limit: ExitQueue::churn_limit(state, config),
        }
    }

    /// The same updates, with activations capped at a fixed count per epoch.
    ///
    /// Deneb caps the activation churn, so the validator set grows at most linearly.
    /// Exits keep the uncapped churn.
    /// See `get_validator_activation_churn_limit` in the Deneb beacon chain spec, and EIP-7514.
    #[must_use]
    pub fn with_activation_cap(self, cap: u64) -> Self {
        Self {
            churn_limit: self.churn_limit.min(cap),
            ..self
        }
    }

    /// Queues full validators, ejects drained ones, then activates the head of the queue.
    ///
    /// # Algorithm
    ///
    /// 1. A validator at the maximum effective balance joins the queue next epoch.
    /// 2. An active validator at or below the ejection balance starts its exit.
    /// 3. Validators whose eligibility is finalized line up by eligibility epoch, then index.
    /// 4. The first churn-limit of them activate.
    ///
    /// # Errors
    ///
    /// Fails when an epoch overflows.
    pub fn apply<S: Fork>(self, registry: &mut Registry<'_, S>) -> Result<(), StateError> {
        let count = registry.state.beacon().validators().len();
        for index in 0..count {
            let validator = &mut registry.state.beacon.validators_mut()[index];
            // Phase0 caps effective balances at the maximum, so only full deposits queue.
            if validator.activation_eligibility_epoch == Epoch::FAR_FUTURE
                && validator.effective_balance == S::Preset::MAX_EFFECTIVE_BALANCE
            {
                validator.activation_eligibility_epoch = self.current + 1;
            }
            if validator.is_active_at(self.current)
                && validator.effective_balance <= self.ejection_balance
            {
                registry.initiate_exit(ValidatorIndex::from(index))?;
            }
        }

        // Invariant: the sort key is unique, since it ends with the index.
        let mut queue: Vec<(Epoch, usize)> = registry
            .state
            .beacon()
            .validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| validator.is_eligible_for_activation(self.finalized))
            .map(|(index, validator)| (validator.activation_eligibility_epoch, index))
            .collect();
        queue.sort_unstable();

        let validators = registry.state.beacon.validators_mut();
        for (_, index) in queue.into_iter().take(self.churn_limit as usize) {
            validators[index].activation_epoch = self.activation_epoch;
        }
        Ok(())
    }
}
