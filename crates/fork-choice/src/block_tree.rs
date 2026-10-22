//! The tree of blocks the store knows, and ancestry queries over it.

use std::collections::HashMap;

use axiom_types::{Hash32, Root, Slot, ValidatorIndex};

/// What the execution engine said about a block's payload.
///
/// See the Bellatrix optimistic sync spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The engine validated the payload.
    #[default]
    Valid,
    /// The engine has not validated the payload yet; the block was imported optimistically.
    Optimistic,
    /// The engine found the payload, or one of its ancestors, invalid.
    Invalid,
}

/// What the fork choice keeps of a block.
///
/// Only the fields the rules read: its place in the tree, its slot, and its proposer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockNode {
    /// Slot the block was proposed in.
    pub slot: Slot,
    /// Root of the parent block.
    pub parent_root: Root,
    /// Validator that proposed the block.
    pub proposer_index: ValidatorIndex,
    /// Hash of the block's execution payload, which the engine knows the block by.
    pub execution_block_hash: Hash32,
    /// Validity of the payload, as far as the engine has told.
    pub status: ExecutionStatus,
}

/// Every block the store accepted, indexed by root, with their children.
///
/// # Invariants
///
/// A block's parent is in the tree, except for the anchor.
/// Blocks arrive parent first, so insertion order is a topological order.
#[derive(Clone, Debug, Default)]
pub struct BlockTree {
    /// Blocks by root.
    nodes: HashMap<Root, BlockNode>,
    /// Children of each block, in insertion order.
    children: HashMap<Root, Vec<Root>>,
    /// Roots in insertion order, parents before children.
    order: Vec<Root>,
}

impl BlockTree {
    /// A tree holding only the anchor block.
    #[must_use]
    pub fn new(anchor_root: Root, anchor: BlockNode) -> Self {
        let mut tree = Self::default();
        tree.insert(anchor_root, anchor);
        tree
    }

    /// Adds a block.
    pub fn insert(&mut self, root: Root, node: BlockNode) {
        if self.nodes.insert(root, node).is_none() {
            self.children
                .entry(node.parent_root)
                .or_default()
                .push(root);
            self.order.push(root);
        }
    }

    /// The block with a root.
    #[must_use]
    pub fn get(&self, root: &Root) -> Option<&BlockNode> {
        self.nodes.get(root)
    }

    /// Whether the tree holds a block.
    #[must_use]
    pub fn contains(&self, root: &Root) -> bool {
        self.nodes.contains_key(root)
    }

    /// Marks a block and its ancestors valid, since a valid payload implies a valid chain.
    pub fn mark_valid(&mut self, root: Root) {
        let mut current = Some(root);
        while let Some(root) = current {
            let Some(node) = self.nodes.get_mut(&root) else {
                break;
            };
            if node.status != ExecutionStatus::Optimistic {
                break;
            }
            node.status = ExecutionStatus::Valid;
            current = Some(node.parent_root);
        }
    }

    /// Marks a block and every descendant invalid, since they all build on an invalid payload.
    pub fn mark_invalid(&mut self, root: Root) {
        let mut stack = vec![root];
        while let Some(root) = stack.pop() {
            if let Some(node) = self.nodes.get_mut(&root) {
                node.status = ExecutionStatus::Invalid;
                stack.extend_from_slice(self.children.get(&root).map_or(&[], Vec::as_slice));
            }
        }
    }

    /// Children of a block, in insertion order.
    #[must_use]
    pub fn children(&self, root: &Root) -> &[Root] {
        self.children.get(root).map_or(&[], Vec::as_slice)
    }

    /// Every block with its root, parents before children.
    #[must_use]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&Root, &BlockNode)> {
        self.order.iter().map(|root| (root, &self.nodes[root]))
    }

    /// The ancestor of a block at a slot: the block itself or its latest ancestor at or before it.
    ///
    /// Returns nothing when the walk leaves the tree.
    /// See `get_ancestor` in the phase0 fork choice spec.
    #[must_use]
    pub fn ancestor(&self, root: Root, slot: Slot) -> Option<Root> {
        let mut current = root;
        loop {
            let node = self.nodes.get(&current)?;
            if node.slot <= slot {
                return Some(current);
            }
            current = node.parent_root;
        }
    }

    /// Whether one block descends from another, or is it.
    ///
    /// See `is_ancestor` in the phase0 fork choice spec.
    #[must_use]
    pub fn is_ancestor(&self, descendant: Root, ancestor: Root) -> bool {
        self.nodes
            .get(&ancestor)
            .is_some_and(|node| self.ancestor(descendant, node.slot) == Some(ancestor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: u8) -> Root {
        Root([tag; 32])
    }

    fn node(slot: u64, parent: u8) -> BlockNode {
        BlockNode {
            slot: Slot(slot),
            parent_root: root(parent),
            proposer_index: ValidatorIndex(0),
            execution_block_hash: Hash32::ZERO,
            status: ExecutionStatus::Valid,
        }
    }

    /// Fixture tree:
    ///
    ///     a(0) -> b(1) -> c(3)
    ///               \
    ///                d(2)
    fn fixture() -> BlockTree {
        let mut tree = BlockTree::new(root(1), node(0, 0));
        tree.insert(root(2), node(1, 1));
        tree.insert(root(3), node(3, 2));
        tree.insert(root(4), node(2, 2));
        tree
    }

    #[test]
    fn ancestor_at_a_skipped_slot_is_the_latest_block_before_it() {
        // Slot 2 is empty on the c branch, so its ancestor there is b at slot 1.
        assert_eq!(fixture().ancestor(root(3), Slot(2)), Some(root(2)));
    }

    #[test]
    fn invalidity_spreads_down_and_validity_up() {
        // Fixture state: b and its descendants c and d are optimistic.
        let mut tree = fixture();
        for tag in 2..=4 {
            tree.nodes.get_mut(&root(tag)).unwrap().status = ExecutionStatus::Optimistic;
        }

        // A valid c vouches for b, but not for its sibling d.
        tree.mark_valid(root(3));
        assert_eq!(tree.get(&root(2)).unwrap().status, ExecutionStatus::Valid);
        assert_eq!(
            tree.get(&root(4)).unwrap().status,
            ExecutionStatus::Optimistic
        );

        // An invalid b condemns both children.
        tree.mark_invalid(root(2));
        assert_eq!(tree.get(&root(3)).unwrap().status, ExecutionStatus::Invalid);
        assert_eq!(tree.get(&root(4)).unwrap().status, ExecutionStatus::Invalid);
    }

    #[test]
    fn ancestry_follows_branches() {
        let tree = fixture();

        assert!(tree.is_ancestor(root(3), root(1)));
        assert!(tree.is_ancestor(root(3), root(3)));
        assert!(!tree.is_ancestor(root(3), root(4)));
        assert_eq!(tree.children(&root(2)), [root(3), root(4)]);
    }
}
