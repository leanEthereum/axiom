//! Deposit requests: deposits relayed by the execution layer.

use axiom_types::{
    accessors::PendingQueueState,
    electra::{DepositRequest, PendingDeposit},
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

/// A deposit request, queued by Fulu's rule.
///
/// Electra also set the deposit requests start index, for the bridge from the old mechanism.
/// Fulu retired the old mechanism, so the request only queues the deposit.
#[derive(Clone, Copy, Debug)]
pub struct QueuedDeposit<'a>(pub &'a DepositRequest);

impl<S: Fork + PendingQueueState> Operation<S> for QueuedDeposit<'_> {
    /// Queues the deposit, stamped with the current slot.
    ///
    /// The slot holds the deposit back until its block is finalized.
    /// See `process_deposit_request` in the Fulu beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let request = self.0;
        let state = &mut *processor.state.beacon;
        let deposit = PendingDeposit {
            pubkey: request.pubkey,
            withdrawal_credentials: request.withdrawal_credentials,
            amount: request.amount,
            signature: request.signature,
            slot: state.slot(),
        };
        state
            .push_pending_deposit(deposit)
            .map_err(|source| StateError::Capacity {
                list: "pending deposits",
                source,
            })?;
        Ok(())
    }
}
