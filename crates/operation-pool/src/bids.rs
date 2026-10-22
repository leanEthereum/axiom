//! Gloas builders' bids for the next block's payload, the best per parent.

use std::collections::BTreeMap;

use axiom_types::{Gwei, Hash32, Root, Slot, gloas::SignedExecutionPayloadBid};

/// The best bid heard for each slot and parent, from Gloas on.
///
/// # Overview
///
/// Builders gossip signed bids for the payload of a coming slot.
/// A bid names the beacon block and the execution block it builds on.
/// A proposer can only take a bid for its own parent, so bids are kept per parent.
///
/// A bid pays its value from the builder's balance, and its execution payment inside the payload.
/// The total ranks the bids.
/// See the Gloas validator spec, section on the signed execution payload bid.
///
/// # Invariants
///
/// Every signature verifies: gossip rules checked each bid on entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BidPool {
    /// The best bid by slot, parent block root, and parent block hash.
    best: BTreeMap<(Slot, Root, Hash32), SignedExecutionPayloadBid>,
}

impl BidPool {
    /// Keeps a bid when it pays more than the best one for its slot and parent.
    pub fn insert(&mut self, bid: SignedExecutionPayloadBid) {
        let message = &bid.message;
        let key = (
            message.slot,
            message.parent_block_root,
            message.parent_block_hash,
        );
        let pays_more = self
            .best
            .get(&key)
            .is_none_or(|known| Self::total(&bid) > Self::total(known));
        if pays_more {
            self.best.insert(key, bid);
        }
    }

    /// The best bid for a slot on a parent.
    #[must_use]
    pub fn best(
        &self,
        slot: Slot,
        parent_block_root: Root,
        parent_block_hash: Hash32,
    ) -> Option<&SignedExecutionPayloadBid> {
        self.best.get(&(slot, parent_block_root, parent_block_hash))
    }

    /// What a bid pays the proposer in all, saturating.
    #[must_use]
    pub const fn total(bid: &SignedExecutionPayloadBid) -> Gwei {
        Gwei(
            bid.message
                .value
                .0
                .saturating_add(bid.message.execution_payment.0),
        )
    }

    /// Drops bids for slots before a given one.
    pub fn prune(&mut self, current: Slot) {
        self.best.retain(|(slot, _, _), _| *slot >= current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bid for slot 5 on a parent, paying a value and an execution payment.
    fn bid(parent: u8, value: u64, payment: u64) -> SignedExecutionPayloadBid {
        let mut bid = SignedExecutionPayloadBid::default();
        bid.message.slot = Slot(5);
        bid.message.parent_block_root = Root([parent; 32]);
        bid.message.value = Gwei(value);
        bid.message.execution_payment = Gwei(payment);
        bid
    }

    #[test]
    fn the_bid_paying_most_in_all_wins_per_parent() {
        let mut pool = BidPool::default();
        // On parent 1: 10 + 0, then 4 + 7 = 11, then 9 + 1 = 10.
        pool.insert(bid(1, 10, 0));
        pool.insert(bid(1, 4, 7));
        pool.insert(bid(1, 9, 1));
        // On parent 2, a smaller bid stands alone.
        pool.insert(bid(2, 1, 0));

        assert_eq!(
            pool.best(Slot(5), Root([1; 32]), Hash32::ZERO),
            Some(&bid(1, 4, 7))
        );
        assert_eq!(
            pool.best(Slot(5), Root([2; 32]), Hash32::ZERO),
            Some(&bid(2, 1, 0))
        );

        // Slot 6 makes every slot 5 bid useless.
        pool.prune(Slot(6));
        assert_eq!(pool.best(Slot(5), Root([1; 32]), Hash32::ZERO), None);
    }
}
