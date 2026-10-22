//! Voluntary exits: a validator asking to stop validating.

use axiom_types::{Domain, Epoch, Preset, SignedVoluntaryExit, constants::DOMAIN_VOLUNTARY_EXIT};

use crate::{BlockError, BlockProcessor, Operation, StateError};

impl<P: Preset> Operation<P> for SignedVoluntaryExit {
    /// Starts the exit of an active, seasoned validator with nothing queued to withdraw.
    ///
    /// The signature domain is pinned to the Capella fork version.
    /// A signed exit therefore stays valid across every later fork, see EIP-7044.
    ///
    /// See `process_voluntary_exit` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let exit = &self.message;
        let state = &processor.state.beacon;
        let epoch = state.current_epoch();
        let validator = state
            .validators
            .get(exit.validator_index.as_usize())
            .ok_or(StateError::UnknownValidator(exit.validator_index))?;

        if !validator.is_active_at(epoch) {
            return Err(BlockError::InvalidVoluntaryExit("validator is not active"));
        }
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Err(BlockError::InvalidVoluntaryExit("exit already initiated"));
        }
        if epoch < exit.epoch {
            return Err(BlockError::InvalidVoluntaryExit("exit is not valid yet"));
        }
        let seasoned = validator
            .activation_epoch
            .checked_add(processor.config.shard_committee_period)
            .is_some_and(|eligible| epoch >= eligible);
        if !seasoned {
            return Err(BlockError::InvalidVoluntaryExit("validator is too recent"));
        }
        if state.pending_balance_to_withdraw(exit.validator_index).0 != 0 {
            return Err(BlockError::InvalidVoluntaryExit("withdrawals are pending"));
        }

        let domain = Domain::compute(
            DOMAIN_VOLUNTARY_EXIT,
            processor.config.capella_fork_version,
            state.genesis_validators_root,
        );
        processor.verify_signature(exit.validator_index, exit, domain, &self.signature)?;

        processor.registry().initiate_exit(exit.validator_index)?;
        Ok(())
    }
}
