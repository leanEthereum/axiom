//! Deposit requests, once the contract deposits are retired.

use axiom_types::{accessors::PendingQueueState, electra::DepositRequest};

use crate::{BlockError, BlockProcessor, Fork, Operation, electra::block::RequestedDeposit};

/// A deposit request, queued by Fulu's rule.
///
/// Electra also set the deposit requests start index, for the bridge from the old mechanism.
/// Fulu retired the old mechanism, so the request only queues the deposit.
#[derive(Clone, Copy, Debug)]
pub struct QueuedDeposit<'a>(pub &'a DepositRequest);

impl<S: Fork + PendingQueueState> Operation<S> for QueuedDeposit<'_> {
    /// Queues the deposit, stamped with the current slot.
    ///
    /// See `process_deposit_request` in the Fulu beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        RequestedDeposit(self.0).queue(&mut *processor.state.beacon)?;
        Ok(())
    }
}
