//! What gossip validation remembers between messages.

use std::collections::HashMap;

use axiom_fork_choice::{BlockNode, ExecutionStatus};
use axiom_gossip::Seen;
use axiom_types::{Preset, Root, SignedBeaconBlock};

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
