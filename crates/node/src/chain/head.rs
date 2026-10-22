//! What the rest of the node needs to know about the canonical chain.

use axiom_types::{Checkpoint, Hash32, Root, Slot};

/// The canonical head and the checkpoints behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// Root of the head block.
    pub root: Root,
    /// Slot of the head block.
    pub slot: Slot,
    /// Whether the engine has yet to validate the head's payload.
    pub optimistic: bool,
    /// The latest justified checkpoint the fork choice uses.
    pub justified: Checkpoint,
    /// The latest finalized checkpoint.
    pub finalized: Checkpoint,
    /// Execution block hashes the engine is told to follow.
    pub execution: ExecutionHead,
}

/// The execution blocks matching the consensus head, safe block, and finalized block.
///
/// These are exactly the three hashes of the engine's fork choice update.
/// See `forkchoiceUpdated` in the Paris engine API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionHead {
    /// Payload hash of the head block.
    pub head: Hash32,
    /// Payload hash of the justified block, which honest validators will not revert.
    pub safe: Hash32,
    /// Payload hash of the finalized block.
    pub finalized: Hash32,
}

/// A change in the chain that other services react to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainEvent {
    /// The head changed.
    Head(Head),
    /// A new checkpoint was finalized.
    Finalized(Checkpoint),
    /// The head moved to a block that does not descend from the previous head.
    Reorg {
        /// Head before the reorg.
        from: Root,
        /// Head after the reorg.
        to: Root,
        /// Blocks between the old head and the common ancestor.
        depth: u64,
    },
}
