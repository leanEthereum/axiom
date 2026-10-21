//! Consolidation requests: merging one validator's stake into another.

use axiom_types::{ConsolidationRequest, Epoch, PendingConsolidation, Preset, ValidatorIndex};

use crate::{BlockError, BlockProcessor, Operation, State, StateError};

impl<P: Preset> Operation<P> for ConsolidationRequest {
    /// Switches a validator to compounding, or queues a consolidation of two validators.
    ///
    /// A request with equal source and target asks to switch to compounding credentials.
    /// Like every execution request, an invalid one is ignored.
    ///
    /// See `process_consolidation_request` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        if let Some(source) = processor.switch_to_compounding_source(self) {
            processor.state.switch_to_compounding_validator(source)?;
            return Ok(());
        }

        // A consolidation into oneself would be an exit that skips the exit queue.
        if self.source_pubkey == self.target_pubkey {
            return Ok(());
        }
        let config = processor.config;
        let total_active_balance = processor.total_active_balance;
        if processor.state.beacon.pending_consolidations.len() as u64
            == P::PENDING_CONSOLIDATIONS_LIMIT
        {
            return Ok(());
        }
        // Threshold: the consolidation churn must exceed one activation balance per epoch.
        if State::<P>::consolidation_churn_limit(config, total_active_balance)
            <= P::MIN_ACTIVATION_BALANCE
        {
            return Ok(());
        }

        let Some(source_index) = processor.state.validator_index(&self.source_pubkey) else {
            return Ok(());
        };
        let Some(target_index) = processor.state.validator_index(&self.target_pubkey) else {
            return Ok(());
        };
        let state = &processor.state.beacon;
        let epoch = state.current_epoch();
        let source = &state.validators[source_index.as_usize()];
        let target = &state.validators[target_index.as_usize()];

        let authorized = source.has_execution_withdrawal_credential()
            && source.withdrawal_address() == self.source_address;
        let seasoned = source
            .activation_epoch
            .checked_add(config.shard_committee_period)
            .is_some_and(|eligible| epoch >= eligible);
        if !authorized
            || !target.has_compounding_withdrawal_credential()
            || !source.is_active_at(epoch)
            || !target.is_active_at(epoch)
            || source.exit_epoch != Epoch::FAR_FUTURE
            || target.exit_epoch != Epoch::FAR_FUTURE
            || !seasoned
            || state.pending_balance_to_withdraw(source_index).0 > 0
        {
            return Ok(());
        }

        let source_balance = source.effective_balance;
        let exit_epoch = processor
            .state
            .compute_consolidation_epoch_and_update_churn(
                config,
                source_balance,
                total_active_balance,
            );
        let state = &mut processor.state.beacon;
        let source = &mut state.validators[source_index.as_usize()];
        source.exit_epoch = exit_epoch;
        source.withdrawable_epoch = exit_epoch
            .checked_add(config.min_validator_withdrawability_delay)
            .ok_or(StateError::Overflow)?;
        state
            .pending_consolidations
            .push(PendingConsolidation {
                source_index,
                target_index,
            })
            .map_err(|_| StateError::ListFull)?;
        Ok(())
    }
}

impl<P: Preset> BlockProcessor<'_, P> {
    /// The validator a request validly asks to switch to compounding credentials, if any.
    ///
    /// See `is_valid_switch_to_compounding_request` in the Electra beacon chain spec.
    fn switch_to_compounding_source(
        &mut self,
        request: &ConsolidationRequest,
    ) -> Option<ValidatorIndex> {
        if request.source_pubkey != request.target_pubkey {
            return None;
        }
        let index = self.state.validator_index(&request.source_pubkey)?;
        let state = &self.state.beacon;
        let validator = &state.validators[index.as_usize()];
        let valid = validator.withdrawal_address() == request.source_address
            && validator.has_eth1_withdrawal_credential()
            && validator.is_active_at(state.current_epoch())
            && validator.exit_epoch == Epoch::FAR_FUTURE;
        valid.then_some(index)
    }
}
