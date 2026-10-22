//! The Gloas head: LMD-GHOST over blocks and the payload variants of each block.

use std::collections::{HashMap, HashSet};

use axiom_state_transition::EpochCommittees;
use axiom_types::{Gwei, Preset, Root, accessors::CoreState};

use super::PayloadTiebreak;
use crate::{BlockNode, ExecutionStatus, ForkChoiceNode, Ghost, NodePayload, PayloadArrival};

/// The parent of the boosted block, when it is from the slot just before.
///
/// Only such a parent can lose the race for the boost, so only its weakness is weighed.
#[derive(Clone, Debug)]
pub(crate) struct BoostParent<'a> {
    /// The parent's root.
    pub(crate) root: Root,
    /// The parent block.
    pub(crate) block: BlockNode,
    /// The committees of the parent's epoch, by the parent's shuffling.
    pub(crate) committees: &'a EpochCommittees,
}

/// The store weighed node by node, the view the Gloas head walk runs on.
///
/// # Overview
///
/// Each block is a pending node with two children: its empty and full variants.
/// The full variant exists once the payload envelope verified.
/// A child block hangs under the variant its bid builds on.
///
/// The walk descends from the justified block, as LMD-GHOST does.
/// Between a block's variants, votes that saw or missed the payload decide.
///
/// For the block of the previous slot, those votes cannot exist yet.
/// Its variants then weigh nothing, and the payload committee's view breaks the tie.
///
/// A block from before Gloas carries its payload, so it has only its full variant.
/// The walk then reduces to the phase0 walk over blocks.
///
/// See `get_head` in the Gloas fork choice spec.
#[derive(Debug)]
pub struct PayloadGhost<'a, P: Preset> {
    /// The store, seen through its justified state.
    ghost: Ghost<'a, P>,
    /// Weight of every node: its attestation score, plus the proposer boost where it applies.
    weights: HashMap<ForkChoiceNode, Gwei>,
    /// Nodes of the justified subtree that lead to a viable leaf.
    viable: HashSet<ForkChoiceNode>,
}

impl<'a, P: Preset> PayloadGhost<'a, P> {
    /// The weighed view of a store.
    pub(crate) fn new(ghost: Ghost<'a, P>, boost_parent: Option<BoostParent<'_>>) -> Self {
        let mut view = Self {
            ghost,
            weights: HashMap::new(),
            viable: HashSet::new(),
        };
        view.weights = view.node_scores();
        if view.should_apply_proposer_boost(boost_parent) {
            view.apply_proposer_boost();
        }
        view.viable = view.viable_nodes();
        view
    }

    /// The head node, never a pending one.
    ///
    /// # Algorithm
    ///
    /// 1. Start at the justified block's pending node.
    /// 2. Step to the viable child with the greatest weight, root, and payload tiebreaker.
    /// 3. Stop at a node without viable children.
    ///
    /// See `get_head` in the Gloas fork choice spec.
    #[must_use]
    pub fn head(&self) -> ForkChoiceNode {
        let justified = self.ghost.store().justified_checkpoint().root;
        if self.viable.is_empty() {
            // Nothing viable: the spec settles on the justified block without its payload.
            // A block from before Gloas has no empty variant, so it stays full.
            return ForkChoiceNode {
                root: justified,
                payload: self.first_variant(justified),
            };
        }
        let mut head = ForkChoiceNode::pending(justified);
        loop {
            let best = self
                .children(head)
                .into_iter()
                .filter(|child| self.viable.contains(child))
                .max_by_key(|child| (self.weight(*child), child.root, self.tiebreaker(*child)));
            match best {
                Some(child) => head = child,
                None => return head,
            }
        }
    }

    /// Leaves of the viable node tree, each with its weight, sorted.
    ///
    /// Spec vectors check these to pin the weights, not just the winner.
    #[must_use]
    pub fn viable_leaves_and_weights(&self) -> Vec<(ForkChoiceNode, Gwei)> {
        let mut leaves: Vec<(ForkChoiceNode, Gwei)> = self
            .viable
            .iter()
            .filter(|node| {
                !self
                    .children(**node)
                    .iter()
                    .any(|child| self.viable.contains(child))
            })
            .map(|node| (*node, self.weight(*node)))
            .collect();
        leaves.sort_by_key(|(node, weight)| (node.root, node.payload.code(), *weight));
        leaves
    }

    /// Weight of a node, nothing for a payload decision of the previous slot.
    ///
    /// See `get_weight` in the Gloas fork choice spec.
    #[must_use]
    pub fn weight(&self, node: ForkChoiceNode) -> Gwei {
        if self.is_previous_slot_payload_decision(node) {
            return Gwei::ZERO;
        }
        self.weights.get(&node).copied().unwrap_or_default()
    }

    /// Attestation score of every node: the stake whose supported node descends from it.
    ///
    /// # Algorithm
    ///
    /// Phase 1 credits each counted vote to the node it supports.
    /// Phase 2 walks the blocks children first.
    /// A block's variants add the pending scores of the children built on them.
    /// Its pending node adds both variants.
    ///
    /// The result equals the spec's per-node sum, in one pass over votes and one over blocks.
    /// See `get_attestation_score` and `is_ancestor` in the Gloas fork choice spec.
    fn node_scores(&self) -> HashMap<ForkChoiceNode, Gwei> {
        let store = self.ghost.store();
        let state = self.ghost.balance_source();
        let epoch = state.current_epoch();

        // Phase 1: direct support.
        let mut direct: HashMap<ForkChoiceNode, Gwei> = HashMap::new();
        for (index, validator) in state.validators().iter().enumerate() {
            if !validator.is_active_at(epoch) || validator.slashed {
                continue;
            }
            if let Some(message) = store.votes.counted(index.into())
                && let Some(node) = store.blocks.supported_node(message)
            {
                *direct.entry(node).or_default() += validator.effective_balance;
            }
        }

        // Phase 2: subtree sums, children before parents.
        let mut scores = direct;
        for (root, block) in store.blocks.iter().rev() {
            let variant = |payload| ForkChoiceNode {
                root: *root,
                payload,
            };
            let empty = scores
                .get(&variant(NodePayload::Empty))
                .copied()
                .unwrap_or_default();
            let full = scores
                .get(&variant(NodePayload::Full))
                .copied()
                .unwrap_or_default();
            let pending = scores.entry(variant(NodePayload::Pending)).or_default();
            *pending += empty + full;
            let pending = *pending;

            // An invalid block passes no weight up, so votes for it support no ancestor.
            if block.status == ExecutionStatus::Invalid || pending == Gwei::ZERO {
                continue;
            }
            if let Some(payload) = store.blocks.parent_payload(root) {
                let parent = ForkChoiceNode {
                    root: block.parent_root,
                    payload,
                };
                *scores.entry(parent).or_default() += pending;
            }
        }
        scores
    }

    /// Whether the boosted block keeps its boost.
    ///
    /// # Overview
    ///
    /// A proposer may build on a weak parent of the previous slot, orphaning it on purpose.
    /// That is the late block reorg, and the boost lets it win.
    ///
    /// An adversarial parent proposer could instead release a second block early.
    /// Withholding the boost from the child of a weak parent then defeats that equivocation.
    /// The boost holds unless such an early equivocation exists.
    ///
    /// See `should_apply_proposer_boost` in the Gloas fork choice spec.
    fn should_apply_proposer_boost(&self, boost_parent: Option<BoostParent<'_>>) -> bool {
        let store = self.ghost.store();
        let boost_root = store.proposer_boost_root();
        let Some(boosted) = store.blocks.get(&boost_root) else {
            return false;
        };
        // A parent from an earlier slot, or none at all, cannot be the weak one.
        let Some(parent) = boost_parent else {
            return true;
        };
        let score = self
            .ghost
            .attestation_scores()
            .get(&parent.root)
            .copied()
            .unwrap_or_default();
        let threshold = self
            .ghost
            .committee_fraction(store.config.reorg_head_weight_threshold);
        if !self
            .ghost
            .is_weak(score, threshold, parent.block.slot, parent.committees)
        {
            return true;
        }
        !store.has_early_equivocation(parent.root, &parent.block, boosted.slot)
    }

    /// Adds the proposer score to the boosted block and to every node it descends from.
    ///
    /// See `get_weight` and `get_proposer_score` in the Gloas fork choice spec.
    fn apply_proposer_boost(&mut self) {
        let store = self.ghost.store();
        let boost = self
            .ghost
            .committee_fraction(store.config.proposer_score_boost);
        let mut current = store.proposer_boost_root();
        *self
            .weights
            .entry(ForkChoiceNode::pending(current))
            .or_default() += boost;
        while let Some(block) = store.blocks.get(&current) {
            let Some(payload) = store.blocks.parent_payload(&current) else {
                break;
            };
            let parent = block.parent_root;
            for node in [
                ForkChoiceNode::pending(parent),
                ForkChoiceNode {
                    root: parent,
                    payload,
                },
            ] {
                *self.weights.entry(node).or_default() += boost;
            }
            current = parent;
        }
    }

    /// Nodes of the justified subtree that lead to a viable leaf.
    ///
    /// A leaf is viable when its block's checkpoints agree with the store's.
    /// An inner node is viable when any of its children is.
    ///
    /// See `get_filtered_node_tree` in the Gloas fork choice spec.
    fn viable_nodes(&self) -> HashSet<ForkChoiceNode> {
        let store = self.ghost.store();

        // Depth-first order from the justified node, so reversing it visits children first.
        let mut order = Vec::new();
        let mut stack = vec![ForkChoiceNode::pending(store.justified_checkpoint().root)];
        while let Some(node) = stack.pop() {
            order.push(node);
            stack.extend(self.children(node));
        }

        let mut viable = HashSet::new();
        for node in order.into_iter().rev() {
            // An invalid payload removes the block and its subtree from consideration.
            if store
                .blocks
                .get(&node.root)
                .is_some_and(|block| block.status == ExecutionStatus::Invalid)
            {
                continue;
            }
            let children = self.children(node);
            let is_viable = if children.is_empty() {
                self.ghost.is_viable_leaf(node.root)
            } else {
                children.iter().any(|child| viable.contains(child))
            };
            if is_viable {
                viable.insert(node);
            }
        }
        viable
    }

    /// The children of a node: a block's variants, or the blocks built on a variant.
    ///
    /// See `get_node_children` in the Gloas fork choice spec.
    fn children(&self, node: ForkChoiceNode) -> Vec<ForkChoiceNode> {
        let blocks = &self.ghost.store().blocks;
        match node.payload {
            NodePayload::Pending => {
                let Some(block) = blocks.get(&node.root) else {
                    return Vec::new();
                };
                let variant = |payload| ForkChoiceNode {
                    root: node.root,
                    payload,
                };
                match block.payload {
                    PayloadArrival::Embedded => vec![variant(NodePayload::Full)],
                    PayloadArrival::Awaited => vec![variant(NodePayload::Empty)],
                    PayloadArrival::Revealed => {
                        vec![variant(NodePayload::Empty), variant(NodePayload::Full)]
                    }
                }
            }
            NodePayload::Empty | NodePayload::Full => blocks
                .children(&node.root)
                .iter()
                .filter(|child| blocks.parent_payload(child) == Some(node.payload))
                .map(|child| ForkChoiceNode::pending(*child))
                .collect(),
        }
    }

    /// The variant a block offers first: full for an embedded payload, empty otherwise.
    fn first_variant(&self, root: Root) -> NodePayload {
        let embedded = self
            .ghost
            .store()
            .blocks
            .get(&root)
            .is_some_and(|block| block.payload == PayloadArrival::Embedded);
        if embedded {
            NodePayload::Full
        } else {
            NodePayload::Empty
        }
    }

    /// Whether a node decides the payload of the block of the previous slot.
    ///
    /// See `is_previous_slot_payload_decision` in the Gloas fork choice spec.
    fn is_previous_slot_payload_decision(&self, node: ForkChoiceNode) -> bool {
        let store = self.ghost.store();
        store.blocks.get(&node.root).is_some_and(|block| {
            PayloadTiebreak::new(store).is_previous_slot_decision(node.payload, block.slot)
        })
    }

    /// The tiebreak between the variants of one block.
    ///
    /// See `get_payload_status_tiebreaker` in the Gloas fork choice spec.
    fn tiebreaker(&self, node: ForkChoiceNode) -> u8 {
        let store = self.ghost.store();
        match store.blocks.get(&node.root) {
            Some(block) => PayloadTiebreak::new(store).tiebreaker(node, block.slot),
            None => node.payload.code(),
        }
    }
}
