//! The deposit queue, drained under the churn.

use axiom_types::{Epoch, Gwei, Preset, Slot, accessors::ParticipationState};

use crate::{
    Registry, StateError,
    electra::{churn::BalanceChurn, deposits::DepositApplication},
};

/// One epoch's pass over the pending deposits, by Electra's rule.
///
/// # Algorithm
///
/// Walk the queue from the front.
///
/// - A deposit request stops the walk while contract deposits before it remain unbridged.
/// - A deposit from a block that is not finalized stops the walk.
/// - A deposit to a withdrawn validator applies without churn, since it never becomes stake.
/// - A deposit to an exiting validator is postponed to the back of the queue.
/// - Any other deposit applies if it fits the remaining churn, and stops the walk otherwise.
///
/// Unused churn carries over only when the walk stopped for lack of churn.
/// A small budget can then accumulate until a large deposit fits.
///
/// Bridged contract deposits carry the genesis slot, and requests a later one.
/// Waiting for the bridge keeps deposits in contract order across the switch, see EIP-6110.
/// See `process_pending_deposits` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositQueue {
    /// The epoch after the ending one.
    next_epoch: Epoch,
    /// Balance this pass may admit: the carried budget plus one epoch's churn.
    available: Gwei,
    /// First slot of the finalized epoch; later deposits wait.
    finalized_slot: Slot,
    /// Whether contract deposits before the first request are still to be bridged.
    bridge_pending: bool,
}

impl DepositQueue {
    /// The pass due at a state, under its registry's churn.
    #[must_use]
    pub fn new<S: BalanceChurn>(registry: &Registry<'_, S>) -> Self {
        let state = registry.state.beacon();
        let churn = S::churn_limits(registry.total_active_balance, registry.config).activation;
        Self {
            next_epoch: state.current_epoch() + 1,
            available: state.deposit_balance_to_consume() + churn,
            finalized_slot: state.finalized_checkpoint().epoch.start_slot::<S::Preset>(),
            bridge_pending: state.eth1_deposit_index() < state.deposit_requests_start_index(),
        }
    }

    /// The same pass with no wait for the bridge, for forks that retired contract deposits.
    #[must_use]
    pub const fn without_bridge(self) -> Self {
        Self {
            bridge_pending: false,
            ..self
        }
    }

    /// Applies queued deposits in order, until the churn or the per-epoch cap runs out.
    ///
    /// # Errors
    ///
    /// Fails when a list is full or a balance overflows.
    pub fn apply<S: BalanceChurn + ParticipationState>(
        self,
        registry: &mut Registry<'_, S>,
    ) -> Result<(), StateError> {
        let config = registry.config;
        let state = &mut registry.state;
        let mut processed_amount = Gwei::ZERO;
        let mut next_deposit = 0;
        let mut postponed = Vec::new();
        let mut churn_limit_reached = false;
        let queue = state.beacon().pending_deposits().to_vec();
        for deposit in &queue {
            // Invariant: only bridged contract deposits carry the genesis slot.
            let is_request = deposit.slot > Slot::GENESIS;
            if (is_request && self.bridge_pending)
                || deposit.slot > self.finalized_slot
                || next_deposit as u64 >= S::Preset::MAX_PENDING_DEPOSITS_PER_EPOCH
            {
                break;
            }
            let (exited, withdrawn) = match state.validator_index(&deposit.pubkey) {
                Some(index) => {
                    let validator = &state.beacon().validators()[index.as_usize()];
                    (
                        validator.exit_epoch < Epoch::FAR_FUTURE,
                        validator.withdrawable_epoch < self.next_epoch,
                    )
                }
                None => (false, false),
            };
            if withdrawn {
                DepositApplication(deposit).apply(state, config)?;
            } else if exited {
                postponed.push(deposit.clone());
            } else {
                let after =
                    processed_amount
                        .checked_add(deposit.amount)
                        .ok_or(StateError::Overflow {
                            quantity: "processed deposit amount",
                        })?;
                churn_limit_reached = after > self.available;
                if churn_limit_reached {
                    break;
                }
                processed_amount = after;
                DepositApplication(deposit).apply(state, config)?;
            }
            next_deposit += 1;
        }
        let beacon = &mut *state.beacon;
        beacon.remove_pending_deposits(next_deposit);
        for deposit in postponed {
            beacon
                .push_pending_deposit(deposit)
                .map_err(|source| StateError::Capacity {
                    list: "pending deposits",
                    source,
                })?;
        }
        *beacon.deposit_balance_to_consume_mut() = if churn_limit_reached {
            self.available - processed_amount
        } else {
            Gwei::ZERO
        };
        Ok(())
    }
}
