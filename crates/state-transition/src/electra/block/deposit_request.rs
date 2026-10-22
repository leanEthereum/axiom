//! Deposit requests: deposits relayed by the execution layer.

use axiom_types::{
    accessors::PendingQueueState,
    constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
    electra::{DepositRequest, PendingDeposit},
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

/// A deposit request, queued by Electra's rule.
///
/// The first request also marks where contract deposits stop, see EIP-6110.
#[derive(Clone, Copy, Debug)]
pub struct RequestedDeposit<'a>(pub &'a DepositRequest);

impl RequestedDeposit<'_> {
    /// Queues the deposit, stamped with the state's slot.
    ///
    /// The slot holds the deposit back until its block is finalized.
    ///
    /// # Errors
    ///
    /// Fails when the deposit queue is full.
    pub fn queue<S: PendingQueueState + ?Sized>(self, state: &mut S) -> Result<(), StateError> {
        let request = self.0;
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
            })
    }
}

impl<S: Fork + PendingQueueState> Operation<S> for RequestedDeposit<'_> {
    /// Records the contract index of the first request, then queues the deposit.
    ///
    /// Contract deposits from that index on arrive as requests, so the bridge stops there.
    /// See `process_deposit_request` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = &mut *processor.state.beacon;
        let start = state.deposit_requests_start_index_mut();
        if *start == UNSET_DEPOSIT_REQUESTS_START_INDEX {
            *start = self.0.index;
        }
        self.queue(state)?;
        Ok(())
    }
}
