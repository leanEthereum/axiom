//! The withdrawals step of Gloas: paying builders and validators before the payload exists.

use axiom_types::{
    BuilderIndex, Gwei, Preset,
    accessors::{BuilderState, PendingQueueState, WithdrawalState},
    capella::Withdrawal,
};

use crate::{
    BlockError, BlockProcessor, Fork, Operation, StateError,
    electra::block::{PayloadWithdrawals, WithdrawalPlan},
};

/// The withdrawals a Gloas block commits the next payload to, and how far each queue advanced.
///
/// See `get_expected_withdrawals` in the Gloas beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedWithdrawals {
    /// The withdrawals, in payload order.
    pub withdrawals: Vec<Withdrawal>,
    /// Builder payments consumed from the front of the builder withdrawal queue.
    pub processed_builder_withdrawals: usize,
    /// Pending partial withdrawals consumed from the front of the queue.
    pub processed_partial_withdrawals: usize,
    /// Builders the builder sweep inspected.
    pub processed_builders_sweep: u64,
    /// Validators the validator sweep inspected.
    pub processed_validators_sweep: u64,
}

impl ExpectedWithdrawals {
    /// The withdrawals due at a state.
    ///
    /// # Algorithm
    ///
    /// 1. Builder payments queued for withdrawal, one short of the payload limit.
    /// 2. Queued partial withdrawals of validators, by Electra's rule.
    /// 3. A sweep over builders, paying out exited builders, one short of the payload limit.
    /// 4. The sweep over validators, by Electra's rule, until the payload is full.
    ///
    /// A withdrawal names a builder by its index with the builder flag set.
    /// The last slot is kept for the validator sweep, so validators always make progress.
    ///
    /// # Errors
    ///
    /// Fails when a cursor or queue entry names no builder or validator.
    pub fn compute<S: BuilderState + PendingQueueState + WithdrawalState>(
        state: &S,
    ) -> Result<Self, StateError> {
        let mut plan = WithdrawalPlan::new(state);
        let processed_builder_withdrawals = Self::builder_payments(&mut plan);
        let processed_partial_withdrawals = plan.pending_partials()?;
        let processed_builders_sweep = Self::builder_sweep(&mut plan)?;
        let processed_validators_sweep = plan.validator_sweep()?;
        Ok(Self {
            withdrawals: plan.withdrawals,
            processed_builder_withdrawals,
            processed_partial_withdrawals,
            processed_builders_sweep,
            processed_validators_sweep,
        })
    }

    /// One short of the payload limit, the room every phase before the validator sweep shares.
    const fn reserved_limit<P: Preset>() -> usize {
        P::MAX_WITHDRAWALS_PER_PAYLOAD as usize - 1
    }

    /// Plans the queued builder payments, returning how many it consumed.
    ///
    /// See `get_builder_withdrawals` in the Gloas beacon chain spec.
    fn builder_payments<S: BuilderState + WithdrawalState>(
        plan: &mut WithdrawalPlan<'_, S>,
    ) -> usize {
        let limit = Self::reserved_limit::<S::Preset>();
        let mut processed = 0;
        for pending in plan.state.builder_pending_withdrawals() {
            if plan.withdrawals.len() >= limit {
                break;
            }
            plan.push(
                pending.builder_index.withdrawal_index(),
                pending.fee_recipient,
                pending.amount,
            );
            processed += 1;
        }
        processed
    }

    /// Plans the sweep over builders, returning how many it inspected.
    ///
    /// A builder whose exit delay passed withdraws its whole balance, net of planned withdrawals.
    /// See `get_builders_sweep_withdrawals` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the sweep cursor names no builder.
    fn builder_sweep<S: BuilderState + WithdrawalState>(
        plan: &mut WithdrawalPlan<'_, S>,
    ) -> Result<u64, StateError> {
        let state = plan.state;
        let epoch = state.current_epoch();
        let builders = state.builders();
        let count = builders.len() as u64;
        let sweep_limit = count.min(S::Preset::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP);
        let limit = Self::reserved_limit::<S::Preset>();
        let mut index = state.next_withdrawal_builder_index();
        let mut processed = 0;
        for _ in 0..sweep_limit {
            if plan.withdrawals.len() >= limit {
                break;
            }
            let builder = builders
                .get(index.as_usize())
                .ok_or(StateError::UnknownBuilder {
                    index,
                    registry_size: builders.len(),
                })?;
            let recipient = index.withdrawal_index();
            // See `get_builder_balance_after_withdrawals` in the Gloas spec, which saturates.
            let balance = builder.balance.saturating_sub(plan.withdrawn(recipient));
            if builder.withdrawable_epoch <= epoch && balance > Gwei::ZERO {
                plan.push(recipient, builder.execution_address, balance);
            }
            index = BuilderIndex((index.0 + 1) % count);
            processed += 1;
        }
        Ok(processed)
    }
}

/// The withdrawals step of a Gloas block, which needs nothing from the block itself.
///
/// The block fixes the withdrawals, pays them at once, and the next payload must carry them.
/// Paying at once keeps the supply sound when the balance would shrink before the payload arrives.
/// A block whose parent payload never arrived skips the step, since its withdrawals are still owed.
///
/// See `process_withdrawals` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommittedWithdrawals;

impl<S> Operation<S> for CommittedWithdrawals
where
    S: Fork + BuilderState + PendingQueueState + WithdrawalState,
{
    /// Computes the withdrawals, pays them, and records them for the payload.
    ///
    /// 1. Skip when the latest bid's payload is not the latest execution block.
    /// 2. Take each withdrawal from its builder or validator.
    /// 3. Record the withdrawals the next payload must carry.
    /// 4. Advance the builder queue, the partial queue, and both sweeps.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = processor.state.beacon();
        // The parent payload is missing, so the withdrawals already paid stay owed to the next one.
        if state.latest_block_hash() != state.latest_execution_payload_bid().block_hash {
            return Ok(());
        }
        let expected = ExpectedWithdrawals::compute(state)?;

        for withdrawal in &expected.withdrawals {
            match withdrawal.validator_index.builder() {
                Some(builder) => {
                    let builders = processor.state.beacon.builders_mut();
                    let registry_size = builders.len();
                    let entry =
                        builders
                            .get_mut(builder.as_usize())
                            .ok_or(StateError::UnknownBuilder {
                                index: builder,
                                registry_size,
                            })?;
                    entry.balance = entry.balance.saturating_sub(withdrawal.amount);
                }
                None => processor
                    .state
                    .decrease_balance(withdrawal.validator_index, withdrawal.amount)?,
            }
        }

        let state = &mut *processor.state.beacon;
        *state.payload_expected_withdrawals_mut() = expected.withdrawals.clone().into();
        state
            .builder_pending_withdrawals_mut()
            .drain(..expected.processed_builder_withdrawals);
        state.remove_pending_partial_withdrawals(expected.processed_partial_withdrawals);
        let builders = state.builders().len() as u64;
        if builders > 0 {
            let cursor = state.next_withdrawal_builder_index_mut();
            *cursor = BuilderIndex((cursor.0 + expected.processed_builders_sweep) % builders);
        }
        PayloadWithdrawals(&expected.withdrawals).advance_cursors(state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Epoch, ExecutionAddress, Minimal, ValidatorIndex, WithdrawalIndex,
        gloas::{BeaconState, Builder, BuilderPendingWithdrawal},
    };

    use super::*;

    #[test]
    fn builder_payments_come_first_under_flagged_indices() {
        // Fixture state: no validator, one builder payment of 5 Gwei owed to builder 2.
        let mut state = BeaconState::<Minimal> {
            next_withdrawal_index: WithdrawalIndex(9),
            ..Default::default()
        };
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                fee_recipient: ExecutionAddress([7; 20]),
                amount: Gwei(5),
                builder_index: BuilderIndex(2),
            });

        let expected = ExpectedWithdrawals::compute(&state).unwrap();

        // One withdrawal, index 9, to builder 2 named as 2^40 + 2.
        assert_eq!(
            expected,
            ExpectedWithdrawals {
                withdrawals: vec![Withdrawal {
                    index: WithdrawalIndex(9),
                    validator_index: ValidatorIndex((1 << 40) + 2),
                    address: ExecutionAddress([7; 20]),
                    amount: Gwei(5),
                }],
                processed_builder_withdrawals: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn the_builder_sweep_pays_exited_builders_net_of_queued_payments() {
        // Fixture state: epoch 0, builder 0 withdrawable at epoch 0 with 30 Gwei.
        // A queued payment already takes 10 Gwei of it, and builder 1 is still active.
        let mut state = BeaconState::<Minimal>::default();
        state.builders.push(Builder {
            balance: Gwei(30),
            execution_address: ExecutionAddress([1; 20]),
            withdrawable_epoch: Epoch(0),
            ..Default::default()
        });
        state.builders.push(Builder {
            balance: Gwei(40),
            withdrawable_epoch: Epoch::FAR_FUTURE,
            ..Default::default()
        });
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                fee_recipient: ExecutionAddress([2; 20]),
                amount: Gwei(10),
                builder_index: BuilderIndex(0),
            });

        let expected = ExpectedWithdrawals::compute(&state).unwrap();

        // The payment pays 10 to the fee recipient, the sweep pays the remaining 20 to the builder.
        let flagged = BuilderIndex(0).withdrawal_index();
        assert_eq!(
            expected,
            ExpectedWithdrawals {
                withdrawals: vec![
                    Withdrawal {
                        index: WithdrawalIndex(0),
                        validator_index: flagged,
                        address: ExecutionAddress([2; 20]),
                        amount: Gwei(10),
                    },
                    Withdrawal {
                        index: WithdrawalIndex(1),
                        validator_index: flagged,
                        address: ExecutionAddress([1; 20]),
                        amount: Gwei(20),
                    },
                ],
                processed_builder_withdrawals: 1,
                processed_partial_withdrawals: 0,
                processed_builders_sweep: 2,
                processed_validators_sweep: 0,
            }
        );
    }
}
