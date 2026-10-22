//! What gossip validation remembers between messages.

use std::collections::HashMap;

use axiom_fork_choice::{BlockNode, ExecutionStatus};
use axiom_gossip::Seen;
use axiom_types::{Preset, Root, SignedBeaconBlock, Slot};

/// Memory of gossip validation that outlives a single message.
///
/// The rules distinguish a parent never seen from one seen but refused.
/// So the node remembers refused blocks, and payloads the engine judged invalid.
#[derive(Debug, Default)]
pub(crate) struct GossipMemory {
    /// Messages already forwarded.
    pub seen: Seen,
    /// Blocks seen but not imported, because they failed.
    pub unimported: HashMap<Root, BlockNode>,
    /// Payload validity of blocks the store does not hold.
    pub payload_statuses: HashMap<Root, ExecutionStatus>,
}

impl GossipMemory {
    /// Forgets refused blocks at or before a slot, which finality made irrelevant.
    ///
    /// A block that old can never be a parent the rules consult again.
    pub(crate) fn prune(&mut self, finalized: Slot) {
        self.unimported.retain(|_, node| node.slot > finalized);
        // Statuses are kept only for blocks still remembered as refused.
        let unimported = &self.unimported;
        self.payload_statuses
            .retain(|root, _| unimported.contains_key(root));
    }

    /// Remembers a block that could not be imported, so its children are refused too.
    pub(crate) fn refuse<P: Preset>(
        &mut self,
        root: Root,
        block: &SignedBeaconBlock<P>,
        invalid_payload: bool,
    ) {
        let message = &block.message;
        self.unimported.insert(
            root,
            BlockNode {
                slot: message.slot,
                parent_root: message.parent_root,
                proposer_index: message.proposer_index,
                execution_block_hash: message.body.execution_payload.block_hash,
                status: ExecutionStatus::Invalid,
            },
        );
        // A consensus failure leaves the payload unjudged; only the engine can condemn it.
        let status = if invalid_payload {
            ExecutionStatus::Invalid
        } else {
            ExecutionStatus::Optimistic
        };
        self.payload_statuses.insert(root, status);
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn finality_forgets_refused_blocks_at_or_before_it() {
        // Fixture state: refused blocks at slots 4 and 9, finality at slot 8.
        let mut memory = GossipMemory::default();
        for slot in [4, 9] {
            let mut block = SignedBeaconBlock::<Minimal>::default();
            block.message.slot = Slot(slot);
            memory.refuse(Root([u8::try_from(slot).unwrap(); 32]), &block, true);
        }

        memory.prune(Slot(8));

        // Only the block after finality remains, with its payload status.
        assert_eq!(
            memory.unimported.keys().copied().collect::<Vec<_>>(),
            [Root([9; 32])]
        );
        assert_eq!(
            memory.payload_statuses.keys().copied().collect::<Vec<_>>(),
            [Root([9; 32])]
        );
    }
}
