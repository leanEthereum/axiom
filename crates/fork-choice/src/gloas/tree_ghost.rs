//! The Gloas head on the weight tree: blocks and payload variants, in two passes over the blocks.

use axiom_types::{Epoch, Gwei, Preset, Root};

use super::PayloadTiebreak;
use crate::{ForkChoiceNode, NodePayload, PayloadArrival, Store, weight_tree::PerNode};

/// What one head selection learns about a block's three nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PayloadMark {
    /// Position of the block's ancestor at the finalized epoch's first slot.
    checkpoint_ancestor: usize,
    /// Whether the walk from the justified block can reach each node.
    reachable: PerNode<bool>,
    /// Whether each node carries the proposer boost.
    boosted: PerNode<bool>,
    /// Whether each node leads to a viable leaf.
    viable: PerNode<bool>,
    /// Whether each node is viable or has a viable node below it, through any block.
    reaches_viable: PerNode<bool>,
    /// The heaviest viable child block of each variant.
    best_child: PerNode<Option<usize>>,
}

/// The store's Gloas head and viable leaves, read off the weight tree.
///
/// # Overview
///
/// Each block is a pending node over its empty and full variants.
/// A child block hangs under the variant its bid builds on.
///
/// A forward pass, parents first, finds checkpoint ancestors and the reachable nodes.
/// A reverse pass, children first, decides viability and each variant's heaviest viable child.
/// The head walk then descends from the justified block's pending node.
///
/// Every rule is the spec's: the same filter, weights, and tiebreaks as the reference view.
/// See `get_head` and `get_filtered_node_tree` in the Gloas fork choice spec.
#[derive(Debug)]
pub(crate) struct TreePayloadGhost<'a, P: Preset> {
    /// The store, its weight tree refreshed.
    store: &'a Store<P>,
    /// One mark per block, in tree order.
    marks: Vec<PayloadMark>,
    /// Position of the justified block.
    justified: usize,
    /// The proposer score the boosted chain carries.
    boost: Gwei,
}

impl<'a, P: Preset> TreePayloadGhost<'a, P> {
    /// Marks the blocks of a store whose justified block is in its weight tree.
    ///
    /// The boost applies only when the store's boost rule granted it.
    /// The marks buffer is reused across heads; its old contents are ignored.
    pub(crate) fn new(
        store: &'a Store<P>,
        justified: usize,
        apply_boost: bool,
        mut marks: Vec<PayloadMark>,
    ) -> Self {
        let nodes = store.weight_tree.nodes();
        marks.clear();
        marks.resize(nodes.len(), PayloadMark::default());

        // Phase 1: checkpoint ancestors and reachable nodes, parents first.
        let finalized_slot = store.finalized_checkpoint().epoch.start_slot::<P>();
        for (index, node) in nodes.iter().enumerate() {
            let parent = node.parent.map(|parent| marks[parent]);
            let mark = &mut marks[index];
            mark.checkpoint_ancestor = match parent {
                Some(parent) if node.slot > finalized_slot => parent.checkpoint_ancestor,
                _ => index,
            };
            let pending = index == justified
                || parent.is_some_and(|parent| *parent.reachable.get(node.parent_payload));
            mark.reachable = PerNode {
                empty: pending && node.arrival.offers(NodePayload::Empty),
                full: pending && node.arrival.offers(NodePayload::Full),
                pending,
            };
        }

        // Phase 2: the boosted block's pending node, and each ancestor's pending node and variant.
        let mut boost = Gwei::ZERO;
        if apply_boost && let Some(boosted) = store.weight_tree.index(&store.proposer_boost_root())
        {
            boost = store
                .weight_tree
                .committee()
                .percent(store.config.proposer_score_boost);
            marks[boosted].boosted.pending = true;
            let mut current = boosted;
            while let Some(parent) = nodes[current].parent {
                marks[parent].boosted.pending = true;
                *marks[parent].boosted.get_mut(nodes[current].parent_payload) = true;
                current = parent;
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

    /// The head node.
    ///
    /// With nothing viable, the spec settles on the justified block without its payload.
    /// A block from before Gloas has no empty variant, so it stays full.
    pub(crate) fn head(&self) -> ForkChoiceNode {
        let nodes = self.store.weight_tree.nodes();
        let justified = &nodes[self.justified];
        if !self.marks[self.justified].reaches_viable.pending {
            let payload = if justified.arrival == PayloadArrival::Embedded {
                NodePayload::Full
            } else {
                NodePayload::Empty
            };
            return ForkChoiceNode {
                root: justified.root,
                payload,
            };
        }
        let mut block = self.justified;
        let mut payload = NodePayload::Pending;
        loop {
            let mark = self.marks[block];
            let next = match payload {
                NodePayload::Pending => [NodePayload::Empty, NodePayload::Full]
                    .into_iter()
                    .filter(|variant| {
                        nodes[block].arrival.offers(*variant) && *mark.viable.get(*variant)
                    })
                    .max_by_key(|variant| self.variant_key(block, *variant))
                    .map(|variant| (block, variant)),
                NodePayload::Empty | NodePayload::Full => mark
                    .best_child
                    .get(payload)
                    .map(|child| (child, NodePayload::Pending)),
            };
            match next {
                Some((next_block, next_payload)) => {
                    block = next_block;
                    payload = next_payload;
                }
                None => {
                    return ForkChoiceNode {
                        root: nodes[block].root,
                        payload,
                    };
                }
            }
        }
    }

    /// Viable leaves reachable from the justified block, each with its weight, sorted.
    pub(crate) fn viable_leaves_and_weights(&self) -> Vec<(ForkChoiceNode, Gwei)> {
        let nodes = self.store.weight_tree.nodes();
        let mut leaves = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let mark = &self.marks[index];
            for payload in [NodePayload::Empty, NodePayload::Full] {
                // Only a variant without children can be a leaf: a viable inner node has a viable child.
                if *mark.reachable.get(payload)
                    && *mark.viable.get(payload)
                    && !node.has_children(payload)
                {
                    let leaf = ForkChoiceNode {
                        root: node.root,
                        payload,
                    };
                    leaves.push((leaf, self.weight(index, payload)));
                }
            }
        }
        leaves.sort_by_key(|(node, weight)| (node.root, node.payload.code(), *weight));
        leaves
    }

    /// Gives back the marks buffer, for the next head.
    pub(crate) fn into_marks(self) -> Vec<PayloadMark> {
        self.marks
    }

    /// Phase 3: viability and heaviest viable children, children first.
    ///
    /// A variant without children is a leaf, viable when its block's checkpoints agree.
    /// A variant with children is viable when one of them is.
    /// A pending node is viable when one of the variants its block offers is.
    /// An invalid block has no viable node, whatever its subtree.
    fn mark_viable(&mut self) {
        let nodes = self.store.weight_tree.nodes();
        for index in (0..nodes.len()).rev() {
            let node = &nodes[index];
            let mut mark = self.marks[index];
            for payload in [NodePayload::Empty, NodePayload::Full] {
                let viable = !node.invalid
                    && if node.has_children(payload) {
                        mark.best_child.get(payload).is_some()
                    } else {
                        self.leaf_agrees(index)
                    };
                *mark.viable.get_mut(payload) = viable;
                *mark.reaches_viable.get_mut(payload) |= viable;
            }
            let offered = |values: &PerNode<bool>| {
                [NodePayload::Empty, NodePayload::Full]
                    .into_iter()
                    .any(|payload| node.arrival.offers(payload) && *values.get(payload))
            };
            mark.viable.pending = offered(&mark.viable);
            mark.reaches_viable.pending = mark.viable.pending || offered(&mark.reaches_viable);
            self.marks[index] = mark;

            if let Some(parent) = node.parent {
                let via = node.parent_payload;
                if mark.reaches_viable.pending {
                    *self.marks[parent].reaches_viable.get_mut(via) = true;
                }
                if mark.viable.pending {
                    let better = self.marks[parent]
                        .best_child
                        .get(via)
                        .is_none_or(|best| self.child_key(index) > self.child_key(best));
                    if better {
                        *self.marks[parent].best_child.get_mut(via) = Some(index);
                    }
                }
            }
        }
    }

    /// Weight of a node: its score plus any boost, nothing for a previous slot's payload decision.
    ///
    /// See `get_weight` in the Gloas fork choice spec.
    fn weight(&self, index: usize, payload: NodePayload) -> Gwei {
        let node = &self.store.weight_tree.nodes()[index];
        if PayloadTiebreak::new(self.store).is_previous_slot_decision(payload, node.slot) {
            return Gwei::ZERO;
        }
        let boost = if *self.marks[index].boosted.get(payload) {
            self.boost
        } else {
            Gwei::ZERO
        };
        *node.scores.get(payload) + boost
    }

    /// The order among the variants of one block: weight, then the payload tiebreak.
    ///
    /// The variants share their root, so the spec's root comparison never decides here.
    fn variant_key(&self, index: usize, payload: NodePayload) -> (Gwei, u8) {
        let node = &self.store.weight_tree.nodes()[index];
        let fork_choice_node = ForkChoiceNode {
            root: node.root,
            payload,
        };
        let tiebreak = PayloadTiebreak::new(self.store).tiebreaker(fork_choice_node, node.slot);
        (self.weight(index, payload), tiebreak)
    }

    /// The order among the child blocks of one variant: pending weight, then the larger root.
    ///
    /// Pending nodes share their tiebreak, so the spec's last comparison never decides here.
    fn child_key(&self, index: usize) -> (Gwei, Root) {
        (
            self.weight(index, NodePayload::Pending),
            self.store.weight_tree.nodes()[index].root,
        )
    }

    /// Whether a block's checkpoints agree with the store's.
    fn leaf_agrees(&self, index: usize) -> bool {
        let store = self.store;
        let nodes = store.weight_tree.nodes();
        let finalized = store.finalized_checkpoint();
        let ancestor = self.marks[index].checkpoint_ancestor;
        let correct_finalized =
            finalized.epoch == Epoch::GENESIS || nodes[ancestor].root == finalized.root;
        correct_finalized && store.agrees_with_justified(nodes[index].root)
    }
}
