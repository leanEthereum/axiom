//! Voluntary exits: a validator asking to stop validating.

use axiom_types::{Epoch, constants::DOMAIN_VOLUNTARY_EXIT, phase0::SignedVoluntaryExit};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork> Operation<S> for SignedVoluntaryExit {
    /// Starts the exit of an active, seasoned validator that signed its request.
    ///
    /// The signature domain follows the fork version at the exit's epoch.
    /// Altair, Bellatrix, and Capella kept this rule.
    /// Deneb pinned the domain to Capella's version, and Electra added a check on withdrawals.
    ///
    /// See `process_voluntary_exit` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let exit = &self.message;
        let state = processor.state.beacon();
        let epoch = state.current_epoch();
        let validators = state.validators();
        let validator = validators.get(exit.validator_index.as_usize()).ok_or(
            StateError::UnknownValidator {
                index: exit.validator_index,
                registry_size: validators.len(),
            },
        )?;
        let invalid = |reason| BlockError::InvalidVoluntaryExit {
            validator: exit.validator_index,
            reason,
        };

        if !validator.is_active_at(epoch) {
            return Err(invalid("validator is not active"));
        }
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Err(invalid("exit already initiated"));
        }
        if epoch < exit.epoch {
            return Err(invalid("exit is not valid yet"));
        }
        let seasoned = validator
            .activation_epoch
            .checked_add(processor.config.shard_committee_period)
            .is_some_and(|eligible| epoch >= eligible);
        if !seasoned {
            return Err(invalid("validator is too recent"));
        }

        let domain = state.domain(DOMAIN_VOLUNTARY_EXIT, exit.epoch);
        processor.verify_signature(exit.validator_index, exit, domain, &self.signature)?;

        processor.registry().initiate_exit(exit.validator_index)?;
        Ok(())
    }
}
