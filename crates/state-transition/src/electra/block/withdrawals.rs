//! The withdrawals step: paying out balances the consensus layer owes.

use std::collections::HashMap;

use axiom_types::{
    ExecutionAddress, Gwei, Preset, Root, ValidatorIndex, WithdrawalIndex,
    accessors::{PendingQueueState, WithdrawalState},
    capella::Withdrawal,
};

use crate::{
    BlockError, BlockProcessor, Fork, Operation, StateError, capella::block::WithdrawalsClaim,
};

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
        let processed_partial_withdrawals = plan.pending_partials()?;
        let processed_sweep = plan.validator_sweep()?;
        Ok(Self {
            withdrawals: plan.withdrawals,
            processed_partial_withdrawals,
            processed_sweep,
        })
    }
}

/// The expected withdrawals under construction, with what each recipient has given so far.
///
/// Each phase of the spec's expected withdrawals is one method.
/// Electra runs two phases, and Gloas wraps them in phases for builders.
#[derive(Debug)]
pub(crate) struct WithdrawalPlan<'a, S: ?Sized> {
    /// The state the withdrawals are due at.
    pub(crate) state: &'a S,
    /// The withdrawals planned so far, in payload order.
    pub(crate) withdrawals: Vec<Withdrawal>,
    /// Total planned per recipient, keyed as the withdrawal names it.
    withdrawn: HashMap<ValidatorIndex, Gwei>,
    /// Index the next withdrawal takes.
    next_index: WithdrawalIndex,
}

impl<'a, S: WithdrawalState + ?Sized> WithdrawalPlan<'a, S> {
    /// An empty plan at a state.
    pub(crate) fn new(state: &'a S) -> Self {
        Self {
            state,
            withdrawals: Vec::new(),
            withdrawn: HashMap::new(),
            next_index: state.next_withdrawal_index(),
        }
    }

    /// Appends a withdrawal and records what it takes from its recipient.
    pub(crate) fn push(
        &mut self,
        validator_index: ValidatorIndex,
        address: ExecutionAddress,
        amount: Gwei,
    ) {
        self.withdrawals.push(Withdrawal {
            index: self.next_index,
            validator_index,
            address,
            amount,
        });
        *self.withdrawn.entry(validator_index).or_default() += amount;
        self.next_index.0 += 1;
    }

    /// Total already planned for a recipient, named as its withdrawals name it.
    pub(crate) fn withdrawn(&self, recipient: ValidatorIndex) -> Gwei {
        self.withdrawn.get(&recipient).copied().unwrap_or_default()
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
            .checked_sub(self.withdrawn(index))
            .ok_or(StateError::Overflow {
                quantity: "balance after withdrawals",
            })
    }

    /// Plans the sweep over validators, returning how many it inspected.
    ///
    /// The sweep starts where the last one stopped, and stops when the payload is full.
    /// See `get_validators_sweep_withdrawals` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the sweep cursor names no validator.
    pub(crate) fn validator_sweep(&mut self) -> Result<u64, StateError> {
        let state = self.state;
        let epoch = state.current_epoch();
        let validators = state.validators();
        let count = validators.len() as u64;
        let sweep_limit = count.min(S::Preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        let mut index = state.next_withdrawal_validator_index();
        let mut processed = 0;
        for _ in 0..sweep_limit {
            if self.withdrawals.len() as u64 >= S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            let validator =
                validators
                    .get(index.as_usize())
                    .ok_or(StateError::UnknownValidator {
                        index,
                        registry_size: validators.len(),
                    })?;
            let balance = self.balance_after(index)?;
            let address = validator.withdrawal_address();
            if validator.is_fully_withdrawable(balance, epoch) {
                self.push(index, address, balance);
            } else if validator.is_partially_withdrawable::<S::Preset>(balance) {
                let excess = balance - validator.max_effective_balance::<S::Preset>();
                self.push(index, address, excess);
            }
            index = ValidatorIndex((index.0 + 1) % count);
            processed += 1;
        }
        Ok(processed)
    }
}

impl<S: PendingQueueState + WithdrawalState + ?Sized> WithdrawalPlan<'_, S> {
    /// Plans the queued partial withdrawals now due, returning how many it consumed.
    ///
    /// Threshold: at most eight beyond those already planned, and one short of the payload limit.
    /// See `get_pending_partial_withdrawals` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a queue entry names no validator.
    pub(crate) fn pending_partials(&mut self) -> Result<usize, StateError> {
        let state = self.state;
        let epoch = state.current_epoch();
        let validators = state.validators();
        let limit = (self.withdrawals.len()
            + S::Preset::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP as usize)
            .min(S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD as usize - 1);
        let mut processed = 0;
        for pending in state.pending_partial_withdrawals() {
            if pending.withdrawable_epoch > epoch || self.withdrawals.len() >= limit {
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
            let balance = self.balance_after(index)?;
            if validator.is_eligible_for_partial_withdrawals::<S::Preset>(balance) {
                let amount = (balance - S::Preset::MIN_ACTIVATION_BALANCE).min(pending.amount);
                self.push(index, validator.withdrawal_address(), amount);
            }
            processed += 1;
        }
        Ok(processed)
    }
}

/// A payload's withdrawals, checked and paid by Electra's rules.
///
/// Electra serves the pending partial withdrawals before the sweep.
/// Capella's rule has no queue, and Gloas moves withdrawals out of the payload.
#[derive(Clone, Copy, Debug)]
pub struct PayloadWithdrawals<'a>(pub WithdrawalsClaim<'a>);

impl<'a> PayloadWithdrawals<'a> {
    /// The withdrawals a whole payload carries.
    #[must_use]
    pub const fn listed(withdrawals: &'a [Withdrawal]) -> Self {
        Self(WithdrawalsClaim::Listed(withdrawals))
    }

    /// The withdrawals a pruned payload's header commits to.
    #[must_use]
    pub const fn committed(root: Root) -> Self {
        Self(WithdrawalsClaim::Committed(root))
    }

    /// Moves the withdrawal index and the validator sweep past the withdrawals paid.
    ///
    /// A full payload resumes the sweep right after its last withdrawal.
    /// Otherwise the sweep advances by its whole window.
    ///
    /// See `update_next_withdrawal_index` and `update_next_withdrawal_validator_index` in Capella.
    pub fn advance_cursors<S: WithdrawalState + ?Sized>(withdrawals: &[Withdrawal], state: &mut S) {
        if let Some(latest) = withdrawals.last() {
            *state.next_withdrawal_index_mut() = WithdrawalIndex(latest.index.0 + 1);
        }
        let count = state.validators().len() as u64;
        let next = match withdrawals.last() {
            Some(latest) if withdrawals.len() as u64 == S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD => {
                latest.validator_index.0 + 1
            }
            _ => {
                state.next_withdrawal_validator_index().0
                    + S::Preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
            }
        };
        *state.next_withdrawal_validator_index_mut() = ValidatorIndex(next % count);
    }
}

impl<S: Fork + PendingQueueState + WithdrawalState> Operation<S> for PayloadWithdrawals<'_> {
    /// Checks a payload's withdrawals against the expected ones, then pays them.
    ///
    /// The payload must carry exactly the expected withdrawals, in order.
    ///
    /// See `process_withdrawals` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let expected = ExpectedWithdrawals::compute(processor.state.beacon())?;
        self.0.check::<S::Preset>(&expected.withdrawals)?;

        for withdrawal in &expected.withdrawals {
            processor
                .state
                .decrease_balance(withdrawal.validator_index, withdrawal.amount)?;
        }

        let state = &mut *processor.state.beacon;
        state.remove_pending_partial_withdrawals(expected.processed_partial_withdrawals);
        PayloadWithdrawals::advance_cursors(&expected.withdrawals, state);
        Ok(())
    }
}
