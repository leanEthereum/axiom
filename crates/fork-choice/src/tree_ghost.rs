//! LMD-GHOST head selection on the weight tree, block by block, in two passes over the blocks.

use axiom_types::{Epoch, Gwei, Preset, Root};

use crate::{NodePayload, Store};

/// What one head selection learns about a block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BlockMark {
    /// Position of the block's ancestor at the finalized epoch's first slot.
    checkpoint_ancestor: usize,
    /// Whether the block is the justified block or descends from it.
    justified_subtree: bool,
    /// Whether the block carries the proposer boost: the boosted block and its ancestors.
    boosted: bool,
    /// Whether the block leads to a viable leaf.
    viable: bool,
    /// The heaviest viable child.
    best_child: Option<usize>,
}

/// The store's head and viable leaves, read off the weight tree.
///
/// # Overview
///
/// A forward pass, parents first, finds each block's finalized checkpoint ancestor.
/// A reverse pass, children first, decides viability and each block's heaviest viable child.
/// The head walk then follows heaviest children down from the justified block.
///
/// Every rule is the spec's: the same filter, weights, and tiebreak as the reference view.
/// See `get_head` and `filter_block_tree` in the phase0 fork choice spec.
#[derive(Debug)]
pub(crate) struct TreeGhost<'a, P: Preset> {
    /// The store, its weight tree refreshed.
    store: &'a Store<P>,
    /// One mark per block, in tree order.
    marks: Vec<BlockMark>,
    /// Position of the justified block.
    justified: usize,
    /// The proposer score the boosted chain carries.
    boost: Gwei,
}

impl<'a, P: Preset> TreeGhost<'a, P> {
    /// Marks the blocks of a store whose justified block is in its weight tree.
    ///
    /// The marks buffer is reused across heads; its old contents are ignored.
    pub(crate) fn new(store: &'a Store<P>, justified: usize, mut marks: Vec<BlockMark>) -> Self {
        let nodes = store.weight_tree.nodes();
        marks.clear();
        marks.resize(nodes.len(), BlockMark::default());

        // Phase 1: checkpoint ancestors and the justified subtree, parents first.
        let finalized_slot = store.finalized_checkpoint().epoch.start_slot::<P>();
        for (index, node) in nodes.iter().enumerate() {
            let parent = node.parent.map(|parent| marks[parent]);
            marks[index].checkpoint_ancestor = match parent {
                // The walk stops at the slot, or at the anchor standing for every slot before it.
                Some(parent) if node.slot > finalized_slot => parent.checkpoint_ancestor,
                _ => index,
            };
            marks[index].justified_subtree =
                index == justified || parent.is_some_and(|parent| parent.justified_subtree);
        }

        // Phase 2: the boosted block and every ancestor carry the boost.
        let mut boost = Gwei::ZERO;
        if let Some(boosted) = store.weight_tree.index(&store.proposer_boost_root()) {
            boost = store
                .weight_tree
                .committee()
                .percent(store.config.proposer_score_boost);
            let mut current = Some(boosted);
            while let Some(index) = current {
                marks[index].boosted = true;
                current = nodes[index].parent;
            }
        }

        let mut view = Self {
            store,
            marks,
            justified,
            boost,
        };
        view.mark_viable();
        view
    }

    /// The head block.
    pub(crate) fn head(&self) -> Root {
        let mut head = self.justified;
        while let Some(child) = self.marks[head].best_child {
            head = child;
        }
        self.store.weight_tree.nodes()[head].root
    }

    /// Viable leaves of the justified subtree, each with its weight, sorted.
    pub(crate) fn viable_leaves_and_weights(&self) -> Vec<(Root, Gwei)> {
        let nodes = self.store.weight_tree.nodes();
        let mut leaves: Vec<(Root, Gwei)> = (0..nodes.len())
            .filter(|index| {
                let mark = self.marks[*index];
                mark.viable && mark.justified_subtree && mark.best_child.is_none()
            })
            .map(|index| (nodes[index].root, self.weight(index)))
            .collect();
        leaves.sort();
        leaves
    }

    /// Gives back the marks buffer, for the next head.
    pub(crate) fn into_marks(self) -> Vec<BlockMark> {
        self.marks
    }

    /// Phase 3: viability and heaviest viable children, children first.
    ///
    /// A leaf is viable when its checkpoints agree with the store's.
    /// An inner block is viable when a child is, so its heaviest viable child exists.
    /// An invalid block is never viable, whatever its subtree.
    fn mark_viable(&mut self) {
        let nodes = self.store.weight_tree.nodes();
        for index in (0..nodes.len()).rev() {
            let node = &nodes[index];
            let is_leaf =
                !node.has_children(NodePayload::Empty) && !node.has_children(NodePayload::Full);
            let viable = !node.invalid
                && if is_leaf {
                    self.leaf_agrees(index)
                } else {
                    self.marks[index].best_child.is_some()
                };
            self.marks[index].viable = viable;
            if let Some(parent) = node.parent
                && viable
            {
                let better = self.marks[parent]
                    .best_child
                    .is_none_or(|best| self.key(index) > self.key(best));
                if better {
                    self.marks[parent].best_child = Some(index);
                }
            }
        }
    }

    /// Weight of a block: its attestation score, plus the boost on the boosted chain.
    ///
    /// See `get_weight` in the phase0 fork choice spec.
    fn weight(&self, index: usize) -> Gwei {
        let node = &self.store.weight_tree.nodes()[index];
        let boost = if self.marks[index].boosted {
            self.boost
        } else {
            Gwei::ZERO
        };
        node.scores.pending + boost
    }

    /// The order among siblings: weight, then the larger root.
    fn key(&self, index: usize) -> (Gwei, Root) {
        (
            self.weight(index),
            self.store.weight_tree.nodes()[index].root,
        )
    }

    /// Whether a leaf's checkpoints agree with the store's.
    fn leaf_agrees(&self, index: usize) -> bool {
        let store = self.store;
        let finalized = store.finalized_checkpoint();
        let ancestor = self.marks[index].checkpoint_ancestor;
        let correct_finalized = finalized.epoch == Epoch::GENESIS
            || store.weight_tree.nodes()[ancestor].root == finalized.root;
        correct_finalized && store.agrees_with_justified(store.weight_tree.nodes()[index].root)
    }
}
