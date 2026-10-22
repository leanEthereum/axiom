//! Consolidation requests: merging one validator's stake into another.

use axiom_types::{
    self, Epoch, Preset,
    electra::{ConsolidationRequest, PendingConsolidation},
};

use crate::{
    BlockError, BlockProcessor, Operation, StateError,
    electra::{churn::BalanceChurn, compounding::CompoundingSwitch},
};

impl<S: BalanceChurn> Operation<S> for ConsolidationRequest {
    /// Switches a validator to compounding, or queues a consolidation of two validators.
    ///
    /// A request with equal source and target asks to switch to compounding credentials.
    /// Like every execution request, an invalid one is ignored.
    ///
    /// No fork rewrote this step; the consolidation churn follows the state's fork.
    /// See `process_consolidation_request` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        // Equal keys ask to switch to compounding credentials.
        // A consolidation into oneself would be an exit that skips the exit queue.
        if self.source_pubkey == self.target_pubkey {
            let Some(index) = processor.state.validator_index(&self.source_pubkey) else {
                return Ok(());
            };
            // See `is_valid_switch_to_compounding_request` in the Electra beacon chain spec.
            let state = processor.state.beacon();
            let validator = &state.validators()[index.as_usize()];
            let valid = validator.withdrawal_address() == self.source_address
                && validator.has_eth1_withdrawal_credential()
                && validator.is_active_at(state.current_epoch())
                && validator.exit_epoch == Epoch::FAR_FUTURE;
            if valid {
                CompoundingSwitch(index).apply(&mut *processor.state.beacon)?;
            }
            return Ok(());
        }
        let config = processor.config;
        if processor.state.beacon().pending_consolidations().len() as u64
            == S::Preset::PENDING_CONSOLIDATIONS_LIMIT
        {
            return Ok(());
        }
        // Threshold: the consolidation churn must exceed one activation balance per epoch.
        let limits = S::churn_limits(processor.total_active_balance, config);
        if limits.consolidation <= S::Preset::MIN_ACTIVATION_BALANCE {
            return Ok(());
        }

        let Some(source_index) = processor.state.validator_index(&self.source_pubkey) else {
            return Ok(());
        };
        let Some(target_index) = processor.state.validator_index(&self.target_pubkey) else {
            return Ok(());
        };
        let state = processor.state.beacon();
        let epoch = state.current_epoch();
        let source = &state.validators()[source_index.as_usize()];
        let target = &state.validators()[target_index.as_usize()];

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
        let mut registry = processor.registry();
        let exit_epoch = S::consolidation_epoch(&mut registry, source_balance);
        let withdrawable_epoch = registry.withdrawable_epoch(exit_epoch)?;
        let state = &mut *processor.state.beacon;
        let source = &mut state.validators_mut()[source_index.as_usize()];
        source.exit_epoch = exit_epoch;
        source.withdrawable_epoch = withdrawable_epoch;
        state
            .push_pending_consolidation(PendingConsolidation {
                source_index,
                target_index,
            })
            .map_err(|source| StateError::Capacity {
                list: "pending consolidations",
                source,
            })?;
        Ok(())
    }
}
