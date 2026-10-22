//! The deposit and consolidation queues, drained under the churn.

use axiom_types::{Epoch, Gwei, Preset};

use super::EpochProcessor;
use crate::{State, StateError};

impl<P: Preset> EpochProcessor<'_, P> {
    /// Applies queued deposits in order, until the churn or the per-epoch cap runs out.
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
    ///
    /// # Errors
    ///
    /// Fails when a list is full or a balance overflows.
    pub fn process_pending_deposits(&mut self) -> Result<(), StateError> {
        let next_epoch = self.current_epoch + 1;
        let churn = State::<P>::activation_exit_churn_limit(self.config, self.total_active_balance);
        let available = self.state.beacon.deposit_balance_to_consume + churn;
        let finalized_slot = self
            .state
            .beacon
            .finalized_checkpoint
            .epoch
            .start_slot::<P>();

        let mut processed_amount = Gwei::ZERO;
        let mut next_deposit = 0;
        let mut postponed = Vec::new();
        let mut churn_limit_reached = false;
        let queue = self.state.beacon.pending_deposits.clone();

        for deposit in &queue {
            if deposit.slot > finalized_slot
                || next_deposit as u64 >= P::MAX_PENDING_DEPOSITS_PER_EPOCH
            {
                break;
            }

            let (exited, withdrawn) = match self.state.validator_index(&deposit.pubkey) {
                Some(index) => {
                    let validator = &self.state.beacon.validators[index.as_usize()];
                    (
                        validator.exit_epoch < Epoch::FAR_FUTURE,
                        validator.withdrawable_epoch < next_epoch,
                    )
                }
                None => (false, false),
            };

            if withdrawn {
                self.state.apply_pending_deposit(self.config, deposit)?;
            } else if exited {
                postponed.push(deposit.clone());
            } else {
                let after = processed_amount
                    .checked_add(deposit.amount)
                    .ok_or(StateError::Overflow)?;
                churn_limit_reached = after > available;
                if churn_limit_reached {
                    break;
                }
                processed_amount = after;
                self.state.apply_pending_deposit(self.config, deposit)?;
            }
            next_deposit += 1;
        }

        let state = &mut self.state.beacon;
        state.pending_deposits.drain(..next_deposit);
        for deposit in postponed {
            state
                .pending_deposits
                .push(deposit)
                .map_err(|_| StateError::ListFull)?;
        }
        state.deposit_balance_to_consume = if churn_limit_reached {
            available - processed_amount
        } else {
            Gwei::ZERO
        };
        Ok(())
    }

    /// Moves the stake of consolidated validators once they become withdrawable.
    ///
    /// Only the active part moves: the lesser of balance and effective balance.
    /// Anything above stays behind to be withdrawn.
    ///
    /// See `process_pending_consolidations` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    pub fn process_pending_consolidations(&mut self) -> Result<(), StateError> {
        let next_epoch = self.current_epoch + 1;
        let mut next_pending = 0;
        let queue = self.state.beacon.pending_consolidations.clone();

        for consolidation in &queue {
            let source = self
                .state
                .beacon
                .validators
                .get(consolidation.source_index.as_usize())
                .ok_or(StateError::UnknownValidator(consolidation.source_index))?;
            if source.slashed {
                next_pending += 1;
                continue;
            }
            if source.withdrawable_epoch > next_epoch {
                break;
            }
            let balance = self.state.beacon.balances[consolidation.source_index.as_usize()];
            let amount = balance.min(source.effective_balance);
            self.state
                .decrease_balance(consolidation.source_index, amount)?;
            self.state
                .increase_balance(consolidation.target_index, amount)?;
            next_pending += 1;
        }

        self.state
            .beacon
            .pending_consolidations
            .drain(..next_pending);
        Ok(())
    }
}
