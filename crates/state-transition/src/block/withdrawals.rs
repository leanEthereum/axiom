//! The withdrawals step: paying out balances the consensus layer owes.

use std::collections::HashMap;

use axiom_types::{
    BeaconState, ExecutionAddress, Gwei, Preset, ValidatorIndex, Withdrawal, WithdrawalIndex,
};

use super::{BlockProcessor, Operation};
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
        let mut plan = WithdrawalPlan::new(state);
        let epoch = state.current_epoch();

        // Phase 1: queued partial withdrawals.
        let partials_limit = (P::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP as usize)
            .min(P::MAX_WITHDRAWALS_PER_PAYLOAD as usize - 1);
        for pending in &state.pending_partial_withdrawals {
            if pending.withdrawable_epoch > epoch
                || plan.expected.withdrawals.len() >= partials_limit
            {
                break;
            }
            let index = pending.validator_index;
            let validator = state
                .validators
                .get(index.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index,
                    registry_size: state.validators.len(),
                })?;
            let balance = plan.balance_after(index)?;
            if validator.is_eligible_for_partial_withdrawals::<P>(balance) {
                let amount = (balance - P::MIN_ACTIVATION_BALANCE).min(pending.amount);
                plan.push(index, validator.withdrawal_address(), amount);
            }
            plan.expected.processed_partial_withdrawals += 1;
        }

        // Phase 2: the validator sweep.
        let count = state.validators.len() as u64;
        let sweep_limit = count.min(P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        let mut index = state.next_withdrawal_validator_index;
        for _ in 0..sweep_limit {
            if plan.expected.withdrawals.len() as u64 >= P::MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            let validator = state
                .validators
                .get(index.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index,
                    registry_size: state.validators.len(),
                })?;
            let balance = plan.balance_after(index)?;
            let address = validator.withdrawal_address();
            if validator.is_fully_withdrawable(balance, epoch) {
                plan.push(index, address, balance);
            } else if validator.is_partially_withdrawable::<P>(balance) {
                let excess = balance - validator.max_effective_balance::<P>();
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
struct WithdrawalPlan<'a, P: Preset> {
    /// The state the withdrawals are due at.
    state: &'a BeaconState<P>,
    /// The withdrawals planned so far.
    expected: ExpectedWithdrawals,
    /// Total planned per validator.
    withdrawn: HashMap<ValidatorIndex, Gwei>,
    /// Index the next withdrawal takes.
    next_index: WithdrawalIndex,
}

impl<'a, P: Preset> WithdrawalPlan<'a, P> {
    /// An empty plan at a state.
    fn new(state: &'a BeaconState<P>) -> Self {
        Self {
            state,
            expected: ExpectedWithdrawals::default(),
            withdrawn: HashMap::new(),
            next_index: state.next_withdrawal_index,
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
        let balance = *self
            .state
            .balances
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: self.state.balances.len(),
            })?;
        balance
            .checked_sub(self.withdrawn.get(&index).copied().unwrap_or_default())
            .ok_or(StateError::Overflow {
                quantity: "balance after withdrawals",
            })
    }
}

impl<P: Preset> Operation<P> for [Withdrawal] {
    /// Checks a payload's withdrawals against the expected ones, then pays them.
    ///
    /// The payload must carry exactly the expected withdrawals, in order.
    ///
    /// See `process_withdrawals` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let expected = ExpectedWithdrawals::compute(&processor.state.beacon)?;
        let expected_withdrawals = expected.withdrawals.as_slice();
        if self != expected_withdrawals {
            return Err(BlockError::WithdrawalsMismatch {
                expected: expected_withdrawals.len(),
                actual: self.len(),
                first_difference: self
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

        let state = &mut processor.state.beacon;
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
