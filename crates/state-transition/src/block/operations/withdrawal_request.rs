//! Withdrawal requests: exits and partial withdrawals triggered from the execution layer.

use axiom_types::{
    Epoch, PendingPartialWithdrawal, Preset, WithdrawalRequest, constants::FULL_EXIT_REQUEST_AMOUNT,
};

use crate::{BlockError, BlockProcessor, Operation, StateError};

impl<P: Preset> Operation<P> for WithdrawalRequest {
    /// Starts an exit, or queues a partial withdrawal, for the request's validator.
    ///
    /// A request that breaks a rule is ignored rather than invalidating the block.
    /// The execution layer already accepted it, so the beacon block cannot refuse it.
    ///
    /// See `process_withdrawal_request` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let is_full_exit = self.amount == FULL_EXIT_REQUEST_AMOUNT;
        let queue_full = processor.state.beacon.pending_partial_withdrawals.len() as u64
            == P::PENDING_PARTIAL_WITHDRAWALS_LIMIT;
        if queue_full && !is_full_exit {
            return Ok(());
        }

        let Some(index) = processor.state.validator_index(&self.validator_pubkey) else {
            return Ok(());
        };
        let config = processor.config;
        let state = &processor.state.beacon;
        let epoch = state.current_epoch();
        let validator = &state.validators[index.as_usize()];

        let authorized = validator.has_execution_withdrawal_credential()
            && validator.withdrawal_address() == self.source_address;
        let seasoned = validator
            .activation_epoch
            .checked_add(config.shard_committee_period)
            .is_some_and(|eligible| epoch >= eligible);
        if !authorized
            || !validator.is_active_at(epoch)
            || validator.exit_epoch != Epoch::FAR_FUTURE
            || !seasoned
        {
            return Ok(());
        }

        let pending = state.pending_balance_to_withdraw(index);
        if is_full_exit {
            // Only exit when nothing is queued, so a queued withdrawal is never stranded.
            if pending.0 == 0 {
                processor.registry().initiate_exit(index)?;
            }
            return Ok(());
        }

        let balance = state.balances[index.as_usize()];
        let has_sufficient_effective_balance =
            validator.effective_balance >= P::MIN_ACTIVATION_BALANCE;
        let floor = P::MIN_ACTIVATION_BALANCE
            .checked_add(pending)
            .ok_or(StateError::Overflow)?;
        let has_excess_balance = balance > floor;
        if validator.has_compounding_withdrawal_credential()
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let to_withdraw = (balance - floor).min(self.amount);
            let mut registry = processor.registry();
            let exit_epoch = registry.exit_epoch(to_withdraw);
            let withdrawable_epoch = registry.withdrawable_epoch(exit_epoch)?;
            processor
                .state
                .beacon
                .pending_partial_withdrawals
                .push(PendingPartialWithdrawal {
                    validator_index: index,
                    amount: to_withdraw,
                    withdrawable_epoch,
                })
                .map_err(|_| StateError::ListFull)?;
        }
        Ok(())
    }
}
