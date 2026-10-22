//! The parent's payload: settling what the previous block's payload did, one block later.

use std::mem;

use axiom_ssz::Ssz;
use axiom_types::{
    Hash32, Preset,
    accessors::BuilderState,
    gloas::{BeaconBlockBody, BuilderPendingWithdrawal, ExecutionRequests},
};

use crate::{
    BlockError, BlockProcessor, Operation, electra::churn::BalanceChurn, fulu::block::QueuedDeposit,
};

/// The parent block's payload, as the child block reports it.
///
/// # Overview
///
/// A Gloas block commits to a payload by its bid, and the payload follows in an envelope.
/// The chain learns whether that payload arrived only from the next block.
/// That block's bid builds either on the parent's payload or on the payload before it.
///
/// - Building on the parent's payload means the parent was full.
///   The block then reports the parent payload's execution requests, which take effect now.
/// - Building on an older payload means the parent was empty, and nothing is reported.
///
/// See EIP-7732 and `process_parent_execution_payload` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct ParentPayload<'a> {
    /// The execution block the child's bid builds on.
    bid_parent_hash: Hash32,
    /// The parent payload's execution requests, as the child reports them.
    requests: &'a ExecutionRequests,
}

impl<'a> ParentPayload<'a> {
    /// The parent payload a block body reports.
    #[must_use]
    pub const fn of<P: Preset>(body: &'a BeaconBlockBody<P>) -> Self {
        Self {
            bid_parent_hash: body.signed_execution_payload_bid.message.parent_block_hash,
            requests: &body.parent_execution_requests,
        }
    }
}

impl<S: BalanceChurn + BuilderState> Operation<S> for ParentPayload<'_> {
    /// Checks the reported requests against the parent's bid, then applies the parent payload.
    ///
    /// Runs before the block's own bid replaces the parent's bid in the state.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let parent_bid = processor.state.beacon().latest_execution_payload_bid();
        if self.bid_parent_hash != parent_bid.block_hash {
            // The parent was empty, so it has no requests to report.
            if *self.requests != ExecutionRequests::default() {
                return Err(BlockError::RequestsOfEmptyParent {
                    bid_parent: self.bid_parent_hash,
                    parent_payload: parent_bid.block_hash,
                });
            }
            return Ok(());
        }
        let actual = self.requests.hash_tree_root();
        if actual != parent_bid.execution_requests_root {
            return Err(BlockError::ParentRequestsRootMismatch {
                committed: parent_bid.execution_requests_root,
                actual,
            });
        }
        processor.apply(&ParentRequests(self.requests))
    }
}

/// The execution requests of a payload that arrived, applied at the child's slot.
///
/// Block production applies them too, before computing the next withdrawals.
/// See `apply_parent_execution_payload` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct ParentRequests<'a>(pub &'a ExecutionRequests);

impl ParentRequests<'_> {
    /// Checks each request list against its per-payload limit.
    ///
    /// Deposit requests carry no check here, as in the spec.
    fn check_limits<P: Preset>(self) -> Result<(), BlockError> {
        let requests = self.0;
        let lists = [
            (
                "withdrawal requests",
                requests.withdrawals.len(),
                P::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            ),
            (
                "consolidation requests",
                requests.consolidations.len(),
                P::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
            ),
            (
                "builder deposit requests",
                requests.builder_deposits.len(),
                P::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
            ),
            (
                "builder exit requests",
                requests.builder_exits.len(),
                P::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
            ),
        ];
        for (operation, count, limit) in lists {
            if count as u64 > limit {
                return Err(BlockError::TooManyOperations {
                    operation,
                    count,
                    limit,
                });
            }
        }
        Ok(())
    }
}

impl<S: BalanceChurn + BuilderState> Operation<S> for ParentRequests<'_> {
    /// Pays the parent's builder, applies the requests, and marks the payload as available.
    ///
    /// # Algorithm
    ///
    /// 1. Settle the parent bid's payment, before any request.
    ///    A builder exit request then sees the payment as owed, and is refused.
    /// 2. Apply the deposit, withdrawal, consolidation, builder deposit, and builder exit requests.
    /// 3. Mark the parent slot's payload as available, and adopt its block hash.
    ///
    /// The payment of a parent in the current or previous epoch waits in its slot's entry.
    /// An older parent's entry was already evicted, so its value is queued directly.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        self.check_limits::<S::Preset>()?;
        let slots = S::Preset::SLOTS_PER_EPOCH;

        // Phase 1: the builder payment.
        let state = &mut *processor.state.beacon;
        let parent_bid = state.latest_execution_payload_bid().clone();
        let parent_slot = state.latest_block_header().slot;
        let parent_epoch = parent_slot.epoch::<S::Preset>();
        let entry = if parent_epoch == state.current_epoch() {
            Some(slots + parent_slot.index_in_epoch::<S::Preset>())
        } else if parent_epoch == state.previous_epoch() {
            Some(parent_slot.index_in_epoch::<S::Preset>())
        } else {
            None
        };
        match entry {
            Some(entry) => {
                let payment = mem::take(&mut state.builder_pending_payments_mut()[entry as usize]);
                if payment.withdrawal.amount.0 > 0 {
                    state
                        .builder_pending_withdrawals_mut()
                        .push(payment.withdrawal);
                }
            }
            None if parent_bid.value.0 > 0 => {
                state
                    .builder_pending_withdrawals_mut()
                    .push(BuilderPendingWithdrawal {
                        fee_recipient: parent_bid.fee_recipient,
                        amount: parent_bid.value,
                        builder_index: parent_bid.builder_index,
                    });
            }
            None => {}
        }

        // Phase 2: the requests, in the order the payload lists their types.
        let requests = self.0;
        for request in &requests.deposits {
            processor.apply(&QueuedDeposit(request))?;
        }
        processor.apply_all(&requests.withdrawals)?;
        processor.apply_all(&requests.consolidations)?;
        processor.apply_all(&requests.builder_deposits)?;
        processor.apply_all(&requests.builder_exits)?;

        // Phase 3: the payload is available, and the execution chain moves to it.
        let state = &mut *processor.state.beacon;
        let position = (parent_slot.0 % S::Preset::SLOTS_PER_HISTORICAL_ROOT) as usize;
        state
            .execution_payload_availability_mut()
            .set(position, true);
        *state.latest_block_hash_mut() = parent_bid.block_hash;
        Ok(())
    }
}
