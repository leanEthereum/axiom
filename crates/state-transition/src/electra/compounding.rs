//! Compounding credentials, and the excess balance they send back through the deposit queue.

use axiom_types::{
    Preset, Slot, ValidatorIndex,
    accessors::PendingQueueState,
    constants::{COMPOUNDING_WITHDRAWAL_PREFIX, G2_POINT_AT_INFINITY},
    electra::PendingDeposit,
};

use crate::StateError;

/// A validator's balance above the activation balance, about to re-enter as a deposit.
///
/// The excess then enters under the churn, like any new stake.
/// See `queue_excess_active_balance` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExcessBalance(pub ValidatorIndex);

impl ExcessBalance {
    /// Moves the excess, if any, from the balance to the back of the deposit queue.
    ///
    /// # Errors
    ///
    /// Fails when the pending deposit queue is full.
    pub fn queue<S: PendingQueueState + ?Sized>(self, state: &mut S) -> Result<(), StateError> {
        let index = self.0.as_usize();
        let balance = state.balances()[index];
        let floor = S::Preset::MIN_ACTIVATION_BALANCE;
        if balance > floor {
            state.balances_mut()[index] = floor;
            let validator = &state.validators()[index];
            let deposit = PendingDeposit {
                pubkey: validator.pubkey,
                withdrawal_credentials: validator.withdrawal_credentials,
                amount: balance - floor,
                // The placeholder signature marks stake whose key was proven already.
                signature: G2_POINT_AT_INFINITY,
                // The genesis slot marks a deposit that needs no finality wait.
                slot: Slot::GENESIS,
            };
            state
                .push_pending_deposit(deposit)
                .map_err(|source| StateError::Capacity {
                    list: "pending deposits",
                    source,
                })?;
        }
        Ok(())
    }
}

/// A validator switching to compounding credentials.
///
/// See `switch_to_compounding_validator` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompoundingSwitch(pub ValidatorIndex);

impl CompoundingSwitch {
    /// Rewrites the credential prefix, and queues the balance above the activation balance.
    ///
    /// # Errors
    ///
    /// Fails when the pending deposit queue is full.
    pub fn apply<S: PendingQueueState + ?Sized>(self, state: &mut S) -> Result<(), StateError> {
        state.validators_mut()[self.0.as_usize()]
            .withdrawal_credentials
            .0[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
        ExcessBalance(self.0).queue(state)
    }
}
