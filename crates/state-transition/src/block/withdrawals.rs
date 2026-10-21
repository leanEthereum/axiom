//! The withdrawals step: paying out balances the consensus layer owes.

use std::collections::HashMap;

use axiom_types::{
    BeaconState, ExecutionAddress, ExecutionPayload, Gwei, Preset, ValidatorIndex, Withdrawal,
    WithdrawalIndex,
};

use super::BlockProcessor;
use crate::{BlockError, StateError};

/// The withdrawals a payload must contain, and how far each queue advanced.
///
/// See `get_expected_withdrawals` in the Electra beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedWithdrawals {
    /// The withdrawals, in payload order.
    pub withdrawals: Vec<Withdrawal>,
    /// Pending partial withdrawals consumed from the front of the queue.
    pub processed_partial_withdrawals: usize,
    /// Validators the sweep inspected.
    pub processed_sweep: u64,
}

impl ExpectedWithdrawals {
    /// The withdrawals due at a state.
    ///
    /// # Algorithm
    ///
    /// Phase 1 serves queued partial withdrawals, at most eight and one short of the payload limit.
    /// Phase 2 sweeps validators from where the last sweep stopped, until the payload is full.
    ///
    /// A validator's balance seen by each phase is net of what earlier withdrawals already took.
    ///
    /// # Errors
    ///
    /// Fails when the state is inconsistent, such as a queue entry naming no validator.
    pub fn compute<P: Preset>(state: &BeaconState<P>) -> Result<Self, StateError> {
        let mut expected = Self::default();
        let mut withdrawn: HashMap<ValidatorIndex, Gwei> = HashMap::new();
        let mut next_index = state.next_withdrawal_index;
        let epoch = state.current_epoch();

        // Phase 1: queued partial withdrawals.
        let partials_limit = (P::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP as usize)
            .min(P::MAX_WITHDRAWALS_PER_PAYLOAD as usize - 1);
        for pending in &state.pending_partial_withdrawals {
            if pending.withdrawable_epoch > epoch || expected.withdrawals.len() >= partials_limit {
                break;
            }
            let index = pending.validator_index;
            let validator = state
                .validators
                .get(index.as_usize())
                .ok_or(StateError::UnknownValidator(index))?;
            let balance = Self::balance_after(state, index, &withdrawn)?;
            if validator.is_eligible_for_partial_withdrawals::<P>(balance) {
                let amount = (balance - P::MIN_ACTIVATION_BALANCE).min(pending.amount);
                expected.push(
                    &mut withdrawn,
                    &mut next_index,
                    index,
                    validator.withdrawal_address(),
                    amount,
                );
            }
            expected.processed_partial_withdrawals += 1;
        }

        // Phase 2: the validator sweep.
        let count = state.validators.len() as u64;
        let sweep_limit = count.min(P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        let mut index = state.next_withdrawal_validator_index;
        for _ in 0..sweep_limit {
            if expected.withdrawals.len() as u64 >= P::MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            let validator = state
                .validators
                .get(index.as_usize())
                .ok_or(StateError::UnknownValidator(index))?;
            let balance = Self::balance_after(state, index, &withdrawn)?;
            let address = validator.withdrawal_address();
            if validator.is_fully_withdrawable(balance, epoch) {
                expected.push(&mut withdrawn, &mut next_index, index, address, balance);
            } else if validator.is_partially_withdrawable::<P>(balance) {
                let excess = balance - validator.max_effective_balance::<P>();
                expected.push(&mut withdrawn, &mut next_index, index, address, excess);
            }
            index = ValidatorIndex((index.0 + 1) % count);
            expected.processed_sweep += 1;
        }

        Ok(expected)
    }

    /// Appends a withdrawal and records what it takes from the validator.
    fn push(
        &mut self,
        withdrawn: &mut HashMap<ValidatorIndex, Gwei>,
        next_index: &mut WithdrawalIndex,
        validator_index: ValidatorIndex,
        address: ExecutionAddress,
        amount: Gwei,
    ) {
        self.withdrawals.push(Withdrawal {
            index: *next_index,
            validator_index,
            address,
            amount,
        });
        *withdrawn.entry(validator_index).or_default() += amount;
        next_index.0 += 1;
    }

    /// A validator's balance net of the withdrawals already planned for it.
    ///
    /// See `get_balance_after_withdrawals` in the Capella beacon chain spec.
    fn balance_after<P: Preset>(
        state: &BeaconState<P>,
        index: ValidatorIndex,
        withdrawn: &HashMap<ValidatorIndex, Gwei>,
    ) -> Result<Gwei, StateError> {
        let balance = *state
            .balances
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator(index))?;
        balance
            .checked_sub(withdrawn.get(&index).copied().unwrap_or_default())
            .ok_or(StateError::Overflow)
    }
}

impl<P: Preset> BlockProcessor<'_, P> {
    /// Checks the payload's withdrawals against the expected ones, then applies them.
    ///
    /// See `process_withdrawals` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the payload's withdrawals are not exactly the expected ones.
    pub fn process_withdrawals(&mut self, payload: &ExecutionPayload<P>) -> Result<(), BlockError> {
        let expected = ExpectedWithdrawals::compute(&self.state.beacon)?;
        if payload.withdrawals.as_slice() != expected.withdrawals.as_slice() {
            return Err(BlockError::WithdrawalsMismatch);
        }

        for withdrawal in &expected.withdrawals {
            self.state
                .decrease_balance(withdrawal.validator_index, withdrawal.amount)?;
        }

        let state = &mut self.state.beacon;
        if let Some(latest) = expected.withdrawals.last() {
            state.next_withdrawal_index = WithdrawalIndex(latest.index.0 + 1);
        }
        state
            .pending_partial_withdrawals
            .drain(..expected.processed_partial_withdrawals);

        // A full payload resumes the sweep right after its last withdrawal.
        // Otherwise the sweep advances by its whole window.
        let count = state.validators.len() as u64;
        let next = match expected.withdrawals.last() {
            Some(latest) if expected.withdrawals.len() as u64 == P::MAX_WITHDRAWALS_PER_PAYLOAD => {
                latest.validator_index.0 + 1
            }
            _ => state.next_withdrawal_validator_index.0 + P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
        };
        state.next_withdrawal_validator_index = ValidatorIndex(next % count);
        Ok(())
    }
}
