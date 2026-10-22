//! Deposit requests: deposits relayed by the execution layer.

use axiom_types::{DepositRequest, PendingDeposit, Preset};

use crate::{BlockError, BlockProcessor, Operation, StateError};

impl<P: Preset> Operation<P> for DepositRequest {
    /// Queues the deposit, stamped with the current slot.
    ///
    /// The slot holds the deposit back until its block is finalized.
    /// See `process_deposit_request` in the Fulu beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let state = &mut processor.state.beacon;
        let deposit = PendingDeposit {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
            signature: self.signature,
            slot: state.slot,
        };
        state
            .pending_deposits
            .push(deposit)
            .map_err(|_| StateError::ListFull)?;
        Ok(())
    }
}
