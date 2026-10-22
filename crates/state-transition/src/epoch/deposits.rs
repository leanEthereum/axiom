//! The deposit queue, drained under the churn.

use axiom_types::{BeaconState, ChainConfig, Epoch, Gwei, Preset, Slot};

use crate::{ActiveBalance, StateError, registry::Registry};

/// One epoch's pass over the pending deposits.
///
/// # Algorithm
///
/// Walk the queue from the front.
///
/// - A deposit from a block that is not finalized stops the walk.
/// - A deposit to a withdrawn validator applies without churn, since it never becomes stake.
/// - A deposit to an exiting validator is postponed to the back of the queue.
/// - Any other deposit applies if it fits the remaining churn, and stops the walk otherwise.
///
/// Unused churn carries over only when the walk stopped for lack of churn.
/// A small budget can then accumulate until a large deposit fits.
///
/// See `process_pending_deposits` in the Fulu beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DepositQueue {
    /// The epoch after the ending one.
    next_epoch: Epoch,
    /// Balance this pass may admit: the carried budget plus one epoch's churn.
    available: Gwei,
    /// First slot of the finalized epoch; later deposits wait.
    finalized_slot: Slot,
}

impl DepositQueue {
    /// The pass due at a state.
    pub(super) fn new<P: Preset>(
        state: &BeaconState<P>,
        config: &ChainConfig,
        total_active_balance: ActiveBalance,
    ) -> Self {
        let churn = total_active_balance.activation_exit_churn_limit::<P>(config);
        Self {
            next_epoch: state.current_epoch() + 1,
            available: state.deposit_balance_to_consume + churn,
            finalized_slot: state.finalized_checkpoint.epoch.start_slot::<P>(),
        }
    }

    /// Applies queued deposits in order, until the churn or the per-epoch cap runs out.
    ///
    /// # Errors
    ///
    /// Fails when a list is full or a balance overflows.
    pub(super) fn apply<P: Preset>(self, registry: &mut Registry<'_, P>) -> Result<(), StateError> {
        let mut processed_amount = Gwei::ZERO;
        let mut next_deposit = 0;
        let mut postponed = Vec::new();
        let mut churn_limit_reached = false;
        let queue = registry.state().beacon.pending_deposits.clone();

        for deposit in &queue {
            if deposit.slot > self.finalized_slot
                || next_deposit as u64 >= P::MAX_PENDING_DEPOSITS_PER_EPOCH
            {
                break;
            }

            let state = registry.state();
            let (exited, withdrawn) = match state.validator_index(&deposit.pubkey) {
                Some(index) => {
                    let validator = &state.beacon.validators[index.as_usize()];
                    (
                        validator.exit_epoch < Epoch::FAR_FUTURE,
                        validator.withdrawable_epoch < self.next_epoch,
                    )
                }
                None => (false, false),
            };

            if withdrawn {
                registry.apply_pending_deposit(deposit)?;
            } else if exited {
                postponed.push(deposit.clone());
            } else {
                let after = processed_amount
                    .checked_add(deposit.amount)
                    .ok_or(StateError::Overflow)?;
                churn_limit_reached = after > self.available;
                if churn_limit_reached {
                    break;
                }
                processed_amount = after;
                registry.apply_pending_deposit(deposit)?;
            }
            next_deposit += 1;
        }

        let state = &mut registry.state().beacon;
        state.pending_deposits.drain(..next_deposit);
        for deposit in postponed {
            state
                .pending_deposits
                .push(deposit)
                .map_err(|_| StateError::ListFull)?;
        }
        state.deposit_balance_to_consume = if churn_limit_reached {
            self.available - processed_amount
        } else {
            Gwei::ZERO
        };
        Ok(())
    }
}
