//! The tree of blocks the store knows, and ancestry queries over it.

use std::collections::{HashMap, HashSet};

use axiom_types::{Epoch, Hash32, Preset, Root, Slot, ValidatorIndex, combined};

use crate::{ForkChoiceNode, LatestMessage, NodePayload};

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

/// Where a block's execution payload is, as far as the store knows.
///
/// See `is_payload_verified` in the Gloas fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadArrival {
    /// The payload rides inside the block, as before Gloas.
    Embedded,
    /// The block commits to a bid, and its envelope has not verified yet.
    Awaited,
    /// The block's envelope arrived and verified.
    Revealed,
}

/// What the fork choice keeps of a block.
///
/// Only the fields the rules read: its place in the tree, its slot, its proposer, and its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockNode {
    /// Slot the block was proposed in.
    pub slot: Slot,
    /// Root of the parent block.
    pub parent_root: Root,
    /// Validator that proposed the block.
    pub proposer_index: ValidatorIndex,
    /// Hash of the execution block the block builds on, zero before the merge.
    pub parent_block_hash: Hash32,
    /// Hash of the execution block the block commits to, zero before the merge.
    pub execution_block_hash: Hash32,
    /// Validity of the payload, as far as the engine has told.
    pub status: ExecutionStatus,
    /// Where the block's payload is.
    pub payload: PayloadArrival,
}

impl BlockNode {
    /// The node of a block of any fork, with what the engine said of its payload.
    ///
    /// A block from Gloas on commits to a bid, and its payload is awaited.
    #[must_use]
    pub const fn of<P: Preset>(block: &combined::BeaconBlock<P>, status: ExecutionStatus) -> Self {
        let hashes = block.execution_hashes();
        Self {
            slot: block.slot(),
            parent_root: block.parent_root(),
            proposer_index: block.proposer_index(),
            parent_block_hash: hashes.parent_block_hash,
            execution_block_hash: hashes.block_hash,
            status,
            payload: if block.fork_name().separates_payloads() {
                PayloadArrival::Awaited
            } else {
                PayloadArrival::Embedded
            },
        }
    }

    /// Whether the block's payload is in hand: embedded, or revealed and verified.
    ///
    /// See `is_payload_verified` in the Gloas fork choice spec.
    #[must_use]
    pub const fn is_payload_verified(&self) -> bool {
        !matches!(self.payload, PayloadArrival::Awaited)
    }

    /// The execution block a confirmed block makes safe.
    ///
    /// Before Gloas that is the block's own payload.
    /// From Gloas on, only the parent payload the bid builds on is known to have run.
    /// See `get_safe_execution_block_hash` in the Bellatrix and Gloas fast confirmation specs.
    #[must_use]
    pub const fn safe_execution_block_hash(&self) -> Hash32 {
        match self.payload {
            PayloadArrival::Embedded => self.execution_block_hash,
            PayloadArrival::Awaited | PayloadArrival::Revealed => self.parent_block_hash,
        }
    }
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
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&Root, &BlockNode)> {
        self.order.iter().map(|root| (root, &self.nodes[root]))
    }

    /// The ancestor of a block at a slot: the block itself or its latest ancestor at or before it.
    ///
    /// The anchor stands for every slot before it, since all history behind it is finalized.
    /// A store anchored mid-epoch then still finds the anchor as its epoch's checkpoint block.
    /// Returns nothing for a block outside the tree.
    /// See `get_ancestor` in the phase0 fork choice spec.
    #[must_use]
    pub fn ancestor(&self, root: Root, slot: Slot) -> Option<Root> {
        let mut current = root;
        loop {
            let node = self.nodes.get(&current)?;
            // The walk stops at the slot, or at the anchor, whose parent the tree never holds.
            if node.slot <= slot || !self.nodes.contains_key(&node.parent_root) {
                return Some(current);
            }
            current = node.parent_root;
        }
    }

    /// Keeps only a block and its descendants, returning the roots dropped.
    ///
    /// The kept block becomes the tree's anchor.
    /// Its parent link stays, though the parent itself is gone.
    pub fn retain_subtree(&mut self, root: Root) -> Vec<Root> {
        // Insertion order is topological, so one forward pass sees every parent first.
        let mut kept = HashSet::from([root]);
        for candidate in &self.order {
            if kept.contains(&self.nodes[candidate].parent_root) {
                kept.insert(*candidate);
            }
        }

        // Split the old order into the surviving roots and the dropped ones.
        let (order, dropped): (Vec<Root>, Vec<Root>) = self
            .order
            .iter()
            .partition(|candidate| kept.contains(candidate));
        // Child lists of kept blocks only ever name kept blocks, so whole lists go or stay.
        self.nodes.retain(|candidate, _| kept.contains(candidate));
        self.children.retain(|parent, _| kept.contains(parent));
        self.order = order;
        dropped
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

    /// Slot of a block, or genesis for a block outside the tree.
    #[must_use]
    pub fn slot_of(&self, root: &Root) -> Slot {
        self.nodes.get(root).map_or(Slot::GENESIS, |node| node.slot)
    }

    /// The chain from just after one block up to and including a descendant, oldest first.
    ///
    /// Returns nothing when the first is not a strict ancestor of the second.
    /// See `get_ancestor_roots` in the phase0 fast confirmation spec.
    #[must_use]
    pub fn chain_after(&self, ancestor: Root, descendant: Root) -> Vec<Root> {
        let ancestor_slot = self.slot_of(&ancestor);
        let mut roots = Vec::new();
        let mut current = descendant;
        while let Some(node) = self.nodes.get(&current) {
            if node.slot <= ancestor_slot {
                break;
            }
            roots.push(current);
            current = node.parent_root;
            if current == ancestor {
                roots.reverse();
                return roots;
            }
        }
        Vec::new()
    }

    /// The block whose randomness fixed an epoch's proposer shuffling, on a block's chain.
    ///
    /// See `get_shuffling_dependent_root` in the phase0 fork choice spec.
    #[must_use]
    pub fn shuffling_dependent_root<P: Preset>(&self, root: Root, epoch: Epoch) -> Option<Root> {
        let lookahead_start = epoch
            .saturating_sub(P::MIN_SEED_LOOKAHEAD)
            .start_slot::<P>();
        self.ancestor(root, lookahead_start.saturating_sub(1))
    }

    /// Whether a block's proposer signed another block for the same slot.
    #[must_use]
    pub fn has_proposer_equivocation(&self, root: Root) -> bool {
        let Some(block) = self.nodes.get(&root) else {
            return false;
        };
        self.iter()
            .filter(|(_, other)| {
                other.proposer_index == block.proposer_index && other.slot == block.slot
            })
            .count()
            > 1
    }

    /// Records that a block's envelope arrived and verified.
    pub fn reveal_payload(&mut self, root: Root) {
        if let Some(node) = self.nodes.get_mut(&root)
            && node.payload == PayloadArrival::Awaited
        {
            node.payload = PayloadArrival::Revealed;
        }
    }

    /// Whether a block builds on its parent's payload or on its parent alone.
    ///
    /// A Gloas bid names the execution block it builds on.
    /// It builds on the parent's payload when that is the payload the parent's bid promised.
    /// A parent from before Gloas carries its payload, so every child builds on it.
    ///
    /// Returns nothing for a block whose parent is outside the tree.
    /// See `get_parent_payload_status` in the Gloas fork choice spec.
    #[must_use]
    pub fn parent_payload(&self, root: &Root) -> Option<NodePayload> {
        let node = self.nodes.get(root)?;
        self.extended_variant(&node.parent_root, node.parent_block_hash)
    }

    /// The variant of a parent that a block building on an execution block extends.
    ///
    /// Returns nothing when the parent is outside the tree.
    /// See `get_parent_payload_status` in the Gloas fork choice spec.
    #[must_use]
    pub fn extended_variant(
        &self,
        parent: &Root,
        parent_block_hash: Hash32,
    ) -> Option<NodePayload> {
        let parent = self.nodes.get(parent)?;
        let full = parent.payload == PayloadArrival::Embedded
            || parent_block_hash == parent.execution_block_hash;
        Some(if full {
            NodePayload::Full
        } else {
            NodePayload::Empty
        })
    }

    /// The node at a slot on a node's chain, keeping the payload status of each step.
    ///
    /// Each step up to a parent takes the payload status its child builds on.
    /// The anchor stands for every slot before it, as in the block form.
    /// See `get_ancestor` in the Gloas fork choice spec.
    #[must_use]
    pub fn ancestor_node(&self, node: ForkChoiceNode, slot: Slot) -> Option<ForkChoiceNode> {
        let mut current = node;
        loop {
            let block = self.nodes.get(&current.root)?;
            if block.slot <= slot {
                return Some(current);
            }
            match self.parent_payload(&current.root) {
                Some(payload) => {
                    current = ForkChoiceNode {
                        root: block.parent_root,
                        payload,
                    };
                }
                // The anchor's parent is gone, so the anchor answers for earlier slots.
                None => return Some(current),
            }
        }
    }

    /// Whether one node descends from another, or is it.
    ///
    /// A pending ancestor matches any payload status of its block.
    /// See `is_ancestor` in the Gloas fork choice spec.
    #[must_use]
    pub fn is_ancestor_node(&self, node: ForkChoiceNode, ancestor: ForkChoiceNode) -> bool {
        let Some(ancestor_block) = self.nodes.get(&ancestor.root) else {
            return false;
        };
        self.ancestor_node(node, ancestor_block.slot)
            .is_some_and(|found| {
                found.root == ancestor.root
                    && (found.payload == ancestor.payload
                        || ancestor.payload == NodePayload::Pending)
            })
    }

    /// The node a vote supports.
    ///
    /// A vote from the block's own slot cannot have seen the payload, so it supports the block.
    /// A later vote supports the variant whose payload it claims to have seen.
    /// A block from before Gloas has only its full variant, whatever the vote says.
    /// See `get_supported_node` in the Gloas fork choice spec.
    #[must_use]
    pub fn supported_node(&self, message: &LatestMessage) -> Option<ForkChoiceNode> {
        let block = self.nodes.get(&message.root)?;
        let payload = match block.payload {
            PayloadArrival::Embedded => NodePayload::Full,
            PayloadArrival::Awaited | PayloadArrival::Revealed if block.slot >= message.slot => {
                NodePayload::Pending
            }
            PayloadArrival::Awaited | PayloadArrival::Revealed if message.payload_present => {
                NodePayload::Full
            }
            PayloadArrival::Awaited | PayloadArrival::Revealed => NodePayload::Empty,
        };
        Some(ForkChoiceNode {
            root: message.root,
            payload,
        })
    }

    /// Invalidates the optimistic blocks an invalid payload condemns.
    ///
    /// The engine names the latest valid ancestor of the invalid payload.
    /// Every block after it on the invalid payload's chain is invalid too.
    ///
    /// | latest valid hash | first invalid block                                    |
    /// |-------------------|--------------------------------------------------------|
    /// | a known hash      | the child of that block on the chain                    |
    /// | unknown or absent | the block whose payload was judged, not yet in the tree |
    ///
    /// See "How to apply latestValidHash" in the Bellatrix optimistic sync spec.
    pub fn invalidate_after(&mut self, parent: Root, latest_valid_hash: Option<Hash32>) {
        let Some(latest_valid_hash) = latest_valid_hash else {
            return;
        };
        let mut child: Option<Root> = None;
        let mut current = parent;
        while let Some(node) = self.nodes.get(&current) {
            if node.execution_block_hash == latest_valid_hash {
                if let Some(first_invalid) = child {
                    self.mark_invalid(first_invalid);
                }
                return;
            }
            child = Some(current);
            current = node.parent_root;
        }
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
            parent_block_hash: Hash32::ZERO,
            execution_block_hash: Hash32::ZERO,
            status: ExecutionStatus::Valid,
            payload: PayloadArrival::Embedded,
        }
    }

    fn bid_node(slot: u64, parent: u8, builds_on: u8, promises: u8) -> BlockNode {
        BlockNode {
            parent_block_hash: Hash32([builds_on; 32]),
            execution_block_hash: Hash32([promises; 32]),
            payload: PayloadArrival::Awaited,
            ..node(slot, parent)
        }
    }

    /// Fixture tree, each block with its slot, each edge from parent to child:
    ///
    /// ```text
    ///     a(0) -> b(1)
    ///     b(1) -> c(3)
    ///     b(1) -> d(2)
    /// ```
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
    fn the_anchor_answers_for_slots_before_it() {
        // Fixture state: a tree anchored mid-epoch at slot 2, with a child at slot 3.
        //
        //     (pruned history) -> a(2) -> b(3)
        let mut tree = BlockTree::new(root(1), node(2, 0));
        tree.insert(root(2), node(3, 1));

        // Slot 0 lies before the anchor, so the anchor is the ancestor there.
        assert_eq!(tree.ancestor(root(2), Slot(0)), Some(root(1)));
        // A block outside the tree has no ancestor at all.
        assert_eq!(tree.ancestor(root(9), Slot(0)), None);
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
    fn retaining_a_subtree_drops_ancestors_and_side_branches() {
        // Fixture state: keep the subtree of b, then add e under the pruned root a.
        //
        //     edges:     a(0) -> b(1), b(1) -> c(3), b(1) -> d(2), a(0) -> e(1)
        //     kept:      b, c, d
        //     dropped:   a, e
        let mut tree = fixture();
        tree.insert(root(5), node(1, 1));

        let mut dropped = tree.retain_subtree(root(2));
        dropped.sort();

        assert_eq!(dropped, [root(1), root(5)]);
        let kept: Vec<Root> = tree.iter().map(|(root, _)| *root).collect();
        assert_eq!(kept, [root(2), root(3), root(4)]);
        assert_eq!(tree.children(&root(2)), [root(3), root(4)]);
        assert_eq!(tree.children(&root(1)), []);
    }

    #[test]
    fn gloas_ancestors_keep_the_payload_status_of_each_step() {
        // Fixture state: Gloas block a(0) promising payload 0xa0, then two children.
        //
        //     b(1) builds on 0xa0, the payload a promised: b extends full a.
        //     c(1) builds on 0x99, the payload before a: c extends empty a.
        let mut tree = BlockTree::new(root(1), bid_node(0, 0, 0x99, 0xa0));
        tree.insert(root(2), bid_node(1, 1, 0xa0, 0xb0));
        tree.insert(root(3), bid_node(1, 1, 0x99, 0xc0));

        assert_eq!(tree.parent_payload(&root(2)), Some(NodePayload::Full));
        assert_eq!(tree.parent_payload(&root(3)), Some(NodePayload::Empty));

        // Walking from pending b back to slot 0 lands on full a.
        let full_a = ForkChoiceNode {
            root: root(1),
            payload: NodePayload::Full,
        };
        let b = ForkChoiceNode::pending(root(2));
        assert_eq!(tree.ancestor_node(b, Slot(0)), Some(full_a));

        // So b descends from full a and pending a, but not from empty a.
        let empty_a = ForkChoiceNode {
            payload: NodePayload::Empty,
            ..full_a
        };
        assert!(tree.is_ancestor_node(b, full_a));
        assert!(tree.is_ancestor_node(b, ForkChoiceNode::pending(root(1))));
        assert!(!tree.is_ancestor_node(b, empty_a));
    }

    #[test]
    fn a_vote_supports_the_variant_it_saw() {
        // Fixture state: Gloas block a at slot 0, and an embedded block e at slot 0.
        let mut tree = BlockTree::new(root(1), bid_node(0, 0, 0x99, 0xa0));
        tree.insert(root(5), node(0, 9));
        let vote = |slot, tag, payload_present| LatestMessage {
            slot: Slot(slot),
            root: root(tag),
            payload_present,
        };
        let at = |tag, payload| ForkChoiceNode {
            root: root(tag),
            payload,
        };

        // A vote in a's own slot supports pending a, whatever it claims.
        assert_eq!(
            tree.supported_node(&vote(0, 1, true)),
            Some(at(1, NodePayload::Pending))
        );
        // A vote one slot later supports the variant it claims.
        assert_eq!(
            tree.supported_node(&vote(1, 1, true)),
            Some(at(1, NodePayload::Full))
        );
        assert_eq!(
            tree.supported_node(&vote(1, 1, false)),
            Some(at(1, NodePayload::Empty))
        );
        // An embedded block only has its full variant.
        assert_eq!(
            tree.supported_node(&vote(0, 5, false)),
            Some(at(5, NodePayload::Full))
        );
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
