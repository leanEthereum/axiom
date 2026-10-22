//! A node of the fork choice tree: a block, and what it says of the block's payload.

use axiom_types::Root;

/// What a fork choice node says about its block's execution payload.
///
/// From Gloas on, each block splits into a pending node and its empty and full variants.
/// The pending node stands for the block before its payload's fate is decided.
///
/// Before Gloas a block carries its payload, so only its full variant exists.
/// See `PayloadStatus` in the Gloas fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodePayload {
    /// The chain goes on without the block's payload.
    Empty,
    /// The chain goes on with the block's payload.
    Full,
    /// The payload's fate is not decided at this node.
    Pending,
}

impl NodePayload {
    /// The spec's number for the status, which also breaks ties between variants of one block.
    ///
    /// See `PAYLOAD_STATUS_EMPTY` and its siblings in the Gloas fork choice spec.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Empty => 0,
            Self::Full => 1,
            Self::Pending => 2,
        }
    }
}

/// A block and what the chain does with its payload.
///
/// See `ForkChoiceNode` in the Gloas fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ForkChoiceNode {
    /// The block.
    pub root: Root,
    /// What the node says of the block's payload.
    pub payload: NodePayload,
}

impl ForkChoiceNode {
    /// The pending node of a block.
    #[must_use]
    pub const fn pending(root: Root) -> Self {
        Self {
            root,
            payload: NodePayload::Pending,
        }
    }
}
