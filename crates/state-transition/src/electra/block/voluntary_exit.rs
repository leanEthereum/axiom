//! Voluntary exits: a validator asking to stop validating.

use axiom_types::{
    Domain, Epoch, accessors::PendingQueueState, constants::DOMAIN_VOLUNTARY_EXIT,
    phase0::SignedVoluntaryExit,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

/// A voluntary exit, checked by Electra's rules.
///
/// Phase0 introduced the operation, and Deneb pinned its signature domain.
/// Electra added the rule that no partial withdrawal may be pending.
#[derive(Clone, Copy, Debug)]
pub struct Exit<'a>(pub &'a SignedVoluntaryExit);

impl<S: Fork + PendingQueueState> Operation<S> for Exit<'_> {
    /// Starts the exit of an active, seasoned validator with nothing queued to withdraw.
    ///
    /// The signature domain is pinned to the Capella fork version.
    /// A signed exit therefore stays valid across every later fork, see EIP-7044.
    ///
    /// See `process_voluntary_exit` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let signed = self.0;
        let exit = &signed.message;
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
        if state.pending_balance_to_withdraw(exit.validator_index).0 != 0 {
            return Err(invalid("withdrawals are pending"));
        }

        let domain = Domain::compute(
            DOMAIN_VOLUNTARY_EXIT,
            processor.config.capella_fork_version,
            state.genesis_validators_root(),
        );
        processor.verify_signature(exit.validator_index, exit, domain, &signed.signature)?;

        processor.registry().initiate_exit(exit.validator_index)?;
        Ok(())
    }
}
