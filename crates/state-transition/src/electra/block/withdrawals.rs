//! The withdrawals step: paying out balances the consensus layer owes.

use std::collections::HashMap;

use axiom_types::{
    ExecutionAddress, Gwei, Preset, ValidatorIndex, WithdrawalIndex,
    accessors::{PendingQueueState, WithdrawalState},
    capella::Withdrawal,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

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
    pub fn compute<S: PendingQueueState + WithdrawalState + ?Sized>(
        state: &S,
    ) -> Result<Self, StateError> {
        let mut plan = WithdrawalPlan::new(state);
        let epoch = state.current_epoch();
        let validators = state.validators();

        // Phase 1: queued partial withdrawals.
        let partials_limit = (S::Preset::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP as usize)
            .min(S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD as usize - 1);
        for pending in state.pending_partial_withdrawals() {
            if pending.withdrawable_epoch > epoch
                || plan.expected.withdrawals.len() >= partials_limit
            {
                break;
            }
            let index = pending.validator_index;
            let validator =
                validators
                    .get(index.as_usize())
                    .ok_or(StateError::UnknownValidator {
                        index,
                        registry_size: validators.len(),
                    })?;
            let balance = plan.balance_after(index)?;
            if validator.is_eligible_for_partial_withdrawals::<S::Preset>(balance) {
                let amount = (balance - S::Preset::MIN_ACTIVATION_BALANCE).min(pending.amount);
                plan.push(index, validator.withdrawal_address(), amount);
            }
            plan.expected.processed_partial_withdrawals += 1;
        }

        // Phase 2: the validator sweep.
        let count = validators.len() as u64;
        let sweep_limit = count.min(S::Preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        let mut index = state.next_withdrawal_validator_index();
        for _ in 0..sweep_limit {
            if plan.expected.withdrawals.len() as u64 >= S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            let validator =
                validators
                    .get(index.as_usize())
                    .ok_or(StateError::UnknownValidator {
                        index,
                        registry_size: validators.len(),
                    })?;
            let balance = plan.balance_after(index)?;
            let address = validator.withdrawal_address();
            if validator.is_fully_withdrawable(balance, epoch) {
                plan.push(index, address, balance);
            } else if validator.is_partially_withdrawable::<S::Preset>(balance) {
                let excess = balance - validator.max_effective_balance::<S::Preset>();
                plan.push(index, address, excess);
            }
            index = ValidatorIndex((index.0 + 1) % count);
            plan.expected.processed_sweep += 1;
        }

        Ok(plan.expected)
    }
}

/// The expected withdrawals under construction, with what each validator has given so far.
#[derive(Debug)]
struct WithdrawalPlan<'a, S: ?Sized> {
    /// The state the withdrawals are due at.
    state: &'a S,
    /// The withdrawals planned so far.
    expected: ExpectedWithdrawals,
    /// Total planned per validator.
    withdrawn: HashMap<ValidatorIndex, Gwei>,
    /// Index the next withdrawal takes.
    next_index: WithdrawalIndex,
}

impl<'a, S: WithdrawalState + ?Sized> WithdrawalPlan<'a, S> {
    /// An empty plan at a state.
    fn new(state: &'a S) -> Self {
        Self {
            state,
            expected: ExpectedWithdrawals::default(),
            withdrawn: HashMap::new(),
            next_index: state.next_withdrawal_index(),
        }
    }

    /// Appends a withdrawal and records what it takes from the validator.
    fn push(&mut self, validator_index: ValidatorIndex, address: ExecutionAddress, amount: Gwei) {
        self.expected.withdrawals.push(Withdrawal {
            index: self.next_index,
            validator_index,
            address,
            amount,
        });
        *self.withdrawn.entry(validator_index).or_default() += amount;
        self.next_index.0 += 1;
    }

    /// A validator's balance net of the withdrawals already planned for it.
    ///
    /// See `get_balance_after_withdrawals` in the Capella beacon chain spec.
    fn balance_after(&self, index: ValidatorIndex) -> Result<Gwei, StateError> {
        let balances = self.state.balances();
        let balance = *balances
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: balances.len(),
            })?;
        balance
            .checked_sub(self.withdrawn.get(&index).copied().unwrap_or_default())
            .ok_or(StateError::Overflow {
                quantity: "balance after withdrawals",
            })
    }
}

/// A payload's withdrawals, checked and paid by Electra's rules.
///
/// Electra serves the pending partial withdrawals before the sweep.
/// Capella's rule has no queue, and Gloas moves withdrawals out of the payload.
#[derive(Clone, Copy, Debug)]
pub struct PayloadWithdrawals<'a>(pub &'a [Withdrawal]);

impl<S: Fork + PendingQueueState + WithdrawalState> Operation<S> for PayloadWithdrawals<'_> {
    /// Checks a payload's withdrawals against the expected ones, then pays them.
    ///
    /// The payload must carry exactly the expected withdrawals, in order.
    ///
    /// See `process_withdrawals` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let actual = self.0;
        let expected = ExpectedWithdrawals::compute(processor.state.beacon())?;
        let expected_withdrawals = expected.withdrawals.as_slice();
        if actual != expected_withdrawals {
            return Err(BlockError::WithdrawalsMismatch {
                expected: expected_withdrawals.len(),
                actual: actual.len(),
                first_difference: actual
                    .iter()
                    .zip(expected_withdrawals)
                    .take_while(|(actual, expected)| actual == expected)
                    .count(),
            });
        }

        for withdrawal in &expected.withdrawals {
            processor
                .state
                .decrease_balance(withdrawal.validator_index, withdrawal.amount)?;
        }

        let state = &mut *processor.state.beacon;
        if let Some(latest) = expected.withdrawals.last() {
            *state.next_withdrawal_index_mut() = WithdrawalIndex(latest.index.0 + 1);
        }
        state.remove_pending_partial_withdrawals(expected.processed_partial_withdrawals);

        // A full payload resumes the sweep right after its last withdrawal.
        // Otherwise the sweep advances by its whole window.
        let count = state.validators().len() as u64;
        let next = match expected.withdrawals.last() {
            Some(latest)
                if expected.withdrawals.len() as u64 == S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD =>
            {
                latest.validator_index.0 + 1
            }
            _ => {
                state.next_withdrawal_validator_index().0
                    + S::Preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
            }
        };
        *state.next_withdrawal_validator_index_mut() = ValidatorIndex(next % count);
        Ok(())
    }
}
