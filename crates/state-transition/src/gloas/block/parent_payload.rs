//! The parent's payload: settling what the previous block's payload did, one block later.

use std::mem;

use axiom_ssz::Ssz;
use axiom_types::{
    Hash32, Preset, Slot,
    accessors::BuilderState,
    gloas::{BeaconBlockBody, BuilderPendingWithdrawal, ExecutionPayloadBid, ExecutionRequests},
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
/// The rule holds for any fork's requests container, which only later forks extend.
/// See EIP-7732 and `process_parent_execution_payload` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct ParentPayload<'a, R> {
    /// The execution block the child's bid builds on.
    bid_parent_hash: Hash32,
    /// The parent payload's execution requests, as the child reports them.
    requests: &'a R,
}

impl<'a, R> ParentPayload<'a, R> {
    /// The parent payload a child reports: the hash its bid builds on, and the requests it carries.
    #[must_use]
    pub const fn new(bid_parent_hash: Hash32, requests: &'a R) -> Self {
        Self {
            bid_parent_hash,
            requests,
        }
    }
}

impl<'a> ParentPayload<'a, ExecutionRequests> {
    /// The parent payload a Gloas block body reports.
    #[must_use]
    pub const fn of<P: Preset>(body: &'a BeaconBlockBody<P>) -> Self {
        Self::new(
            body.signed_execution_payload_bid.message.parent_block_hash,
            &body.parent_execution_requests,
        )
    }
}

impl<S, R> Operation<S> for ParentPayload<'_, R>
where
    S: BalanceChurn + BuilderState,
    R: Ssz + Default + PartialEq,
    for<'b> ParentRequests<'b, R>: Operation<S>,
{
    /// Checks the reported requests against the parent's bid, then applies the parent payload.
    ///
    /// Runs before the block's own bid replaces the parent's bid in the state.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let parent_bid = processor.state.beacon().latest_execution_payload_bid();
        if self.bid_parent_hash != parent_bid.block_hash {
            // The parent was empty, so it has no requests to report.
            if *self.requests != R::default() {
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
/// Each fork's requests container applies by that fork's rule.
/// Block production applies them too, before computing the next withdrawals.
/// See `apply_parent_execution_payload` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct ParentRequests<'a, R>(pub &'a R);

impl ParentRequests<'_, ExecutionRequests> {
    /// Checks each request list against its per-payload limit.
    ///
    /// Deposit requests carry no check here, as in the spec.
    fn check_limits<P: Preset>(&self) -> Result<(), BlockError> {
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

impl<S: BalanceChurn + BuilderState> Operation<S> for ParentRequests<'_, ExecutionRequests> {
    /// Pays the parent's builder, applies the requests, and marks the payload as available.
    ///
    /// # Algorithm
    ///
    /// 1. Settle the parent bid's payment, before any request.
    ///    A builder exit request then sees the payment as owed, and is refused.
    /// 2. Apply the deposit, withdrawal, consolidation, builder deposit, and builder exit requests.
    /// 3. Mark the parent slot's payload as available, and adopt its block hash.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        self.check_limits::<S::Preset>()?;

        // Phase 1: the builder payment.
        let parent = ArrivedParentBid::of(&*processor.state.beacon);
        parent.pay(&mut *processor.state.beacon);

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
        parent.deliver(&mut *processor.state.beacon);
        Ok(())
    }
}

/// The parent block's bid, once the child shows that its payload arrived.
///
/// Its payment and its delivery bracket the payload's requests, whatever the fork's requests are.
/// See `apply_parent_execution_payload` in the Gloas beacon chain spec.
#[derive(Clone, Debug)]
pub struct ArrivedParentBid {
    /// The bid the parent block committed to.
    bid: ExecutionPayloadBid,
    /// Slot of the parent block.
    slot: Slot,
}

impl ArrivedParentBid {
    /// The bid of the state's latest block, before the child's bid replaces it.
    #[must_use]
    pub fn of<S: BuilderState>(state: &S) -> Self {
        Self {
            bid: state.latest_execution_payload_bid().clone(),
            slot: state.latest_block_header().slot,
        }
    }

    /// Moves the bid's payment to the builder withdrawal queue.
    ///
    /// The payment of a parent in the current or previous epoch waits in its slot's entry.
    /// An older parent's entry was already evicted, so its value is queued directly.
    pub fn pay<S: BuilderState>(&self, state: &mut S) {
        let slots = S::Preset::SLOTS_PER_EPOCH;
        let epoch = self.slot.epoch::<S::Preset>();

        // Entries hold the previous epoch's slots first, then the current epoch's.
        //
        //     entry = SLOTS_PER_EPOCH * [epoch is current] + slot % SLOTS_PER_EPOCH
        let entry = if epoch == state.current_epoch() {
            Some(slots + self.slot.index_in_epoch::<S::Preset>())
        } else if epoch == state.previous_epoch() {
            Some(self.slot.index_in_epoch::<S::Preset>())
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
            None if self.bid.value.0 > 0 => {
                state
                    .builder_pending_withdrawals_mut()
                    .push(BuilderPendingWithdrawal {
                        fee_recipient: self.bid.fee_recipient,
                        amount: self.bid.value,
                        builder_index: self.bid.builder_index,
                    });
            }
            None => {}
        }
    }

    /// Marks the parent slot's payload as available, and moves the execution chain to it.
    pub fn deliver<S: BuilderState>(&self, state: &mut S) {
        let position = (self.slot.0 % S::Preset::SLOTS_PER_HISTORICAL_ROOT) as usize;
        state
            .execution_payload_availability_mut()
            .set(position, true);
        *state.latest_block_hash_mut() = self.bid.block_hash;
    }
}
