//! The Gloas head: a block, and whether the chain goes on with its payload or without it.

use std::collections::{HashMap, HashSet};

use axiom_fork_choice::ForkChoiceError;
use axiom_types::{Gwei, Preset, Root};

use crate::ChainView;

/// Whether a fork choice node stands for a block, its payload, or its missing payload.
///
/// The order is the spec's tiebreak order between nodes of one block.
/// See `PayloadStatus` in the Gloas fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NodePayload {
    /// The block, before its payload's fate is decided.
    Pending,
    /// The block without its payload.
    Empty,
    /// The block with its payload.
    Full,
}

/// A node of the Gloas fork choice tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadNode {
    /// The block.
    pub(crate) root: Root,
    /// What the node says of the block's payload.
    pub(crate) payload: NodePayload,
}

/// The inputs of the Gloas head walk, gathered once from a view.
///
/// # Overview
///
/// Each block splits into an empty node and, once its payload arrived, a full node.
/// A child hangs under the node its bid builds on.
/// The walk descends from the justified block to the heaviest child, as LMD-GHOST does.
///
/// The store weighs blocks, not payload nodes, and records no payload timeliness votes.
/// Both nodes of a block therefore carry the block's weight, and no vote tips a payload decision.
/// See `get_head` in the Gloas fork choice spec.
#[derive(Debug)]
pub(crate) struct PayloadHead<'v, 'a, P: Preset> {
    /// The chain.
    view: &'v ChainView<'a, P>,
    /// Weight of each block.
    weights: HashMap<Root, Gwei>,
    /// Blocks whose branch can still win.
    viable: HashSet<Root>,
}

impl<'v, 'a, P: Preset> PayloadHead<'v, 'a, P> {
    /// The head walk over a view.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub(crate) fn of(view: &'v mut ChainView<'a, P>) -> Result<Self, ForkChoiceError> {
        let (weights, viable) = {
            let ghost = view.store.ghost()?;
            (ghost.weights(), ghost.viable_nodes())
        };
        Ok(Self {
            view,
            weights,
            viable,
        })
    }

    /// The head node.
    ///
    /// See `get_head` in the Gloas fork choice spec.
    pub(crate) fn head(&self) -> PayloadNode {
        let mut head = PayloadNode {
            root: self.view.store.justified_checkpoint().root,
            payload: NodePayload::Pending,
        };
        loop {
            let Some(next) = self
                .children(head)
                .into_iter()
                .max_by_key(|child| (self.weight(*child), child.root, self.tiebreaker(*child)))
            else {
                return head;
            };
            head = next;
        }
    }

    /// Whether a block's child builds on the block's payload.
    ///
    /// See `get_parent_payload_status` in the Gloas fork choice spec.
    pub(crate) fn builds_on_full(view: &ChainView<'_, P>, child: &Root) -> bool {
        let Some(parent) = view.block(child).map(|node| node.parent_root) else {
            return false;
        };
        let promised = view.block(&parent).map(|node| node.execution_block_hash);
        view.bids
            .get(child)
            .is_some_and(|bid| Some(bid.parent_block_hash) == promised)
    }

    /// The viable children of a node.
    ///
    /// See `get_node_children` in the Gloas fork choice spec.
    fn children(&self, node: PayloadNode) -> Vec<PayloadNode> {
        if node.payload == NodePayload::Pending {
            let mut children = vec![PayloadNode {
                root: node.root,
                payload: NodePayload::Empty,
            }];
            if self.view.is_payload_verified(&node.root) {
                children.push(PayloadNode {
                    root: node.root,
                    payload: NodePayload::Full,
                });
            }
            return children;
        }
        let wants_full = node.payload == NodePayload::Full;
        self.view
            .store
            .blocks()
            .children(&node.root)
            .iter()
            .filter(|child| self.viable.contains(child))
            .filter(|child| Self::builds_on_full(self.view, child) == wants_full)
            .map(|child| PayloadNode {
                root: *child,
                payload: NodePayload::Pending,
            })
            .collect()
    }

    /// The node's weight, nothing for a payload decision of the previous slot.
    ///
    /// See `get_weight` in the Gloas fork choice spec.
    fn weight(&self, node: PayloadNode) -> Gwei {
        if self.is_previous_slot_decision(node) {
            return Gwei(0);
        }
        self.weights.get(&node.root).copied().unwrap_or_default()
    }

    /// The tiebreak between the payload nodes of one block.
    ///
    /// See `get_payload_status_tiebreaker` in the Gloas fork choice spec.
    fn tiebreaker(&self, node: PayloadNode) -> u8 {
        if !self.is_previous_slot_decision(node) {
            return node.payload as u8;
        }
        match node.payload {
            NodePayload::Empty => 1,
            NodePayload::Full if self.should_extend_payload(node.root) => 2,
            NodePayload::Pending | NodePayload::Full => 0,
        }
    }

    /// Whether a node decides the payload of the block just before the current slot.
    ///
    /// See `is_previous_slot_payload_decision` in the Gloas fork choice spec.
    fn is_previous_slot_decision(&self, node: PayloadNode) -> bool {
        let current = self.view.store.current_slot();
        node.payload != NodePayload::Pending
            && self
                .view
                .block(&node.root)
                .is_some_and(|block| block.slot + 1 == current)
    }

    /// Whether the chain should go on with a block's payload.
    ///
    /// Without timeliness votes, only the boosted proposal can argue for the empty node.
    /// See `should_extend_payload` in the Gloas fork choice spec.
    fn should_extend_payload(&self, root: Root) -> bool {
        if !self.view.is_payload_verified(&root) {
            return false;
        }
        let boost = self.view.store.proposer_boost_root();
        if boost == Root::ZERO {
            return true;
        }
        self.view.block(&boost).is_none_or(|block| {
            block.parent_root != root || Self::builds_on_full(self.view, &boost)
        })
    }
}
