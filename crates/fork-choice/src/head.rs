//! LMD-GHOST head selection over the viable part of the block tree.

use std::collections::{HashMap, HashSet};

use axiom_types::{BeaconState, Epoch, Gwei, Preset, Root};

use crate::{ExecutionStatus, Store, committee_weight::CommitteeWeight};

/// The store seen through a balance source, the view LMD-GHOST runs on.
///
/// # Overview
///
/// The balance source's validator set weighs every vote.
/// Its committee weight sizes the proposer boost.
/// Head selection uses the justified checkpoint state, fast confirmation other checkpoints.
/// The view borrows both, so the weights and the head are pure functions of it.
#[derive(Clone, Copy, Debug)]
pub struct Ghost<'a, P: Preset> {
    /// The store.
    store: &'a Store<P>,
    /// The state whose validator set weighs the votes.
    balance_source: &'a BeaconState<P>,
}

impl<'a, P: Preset> Ghost<'a, P> {
    /// The view of a store through a balance source.
    pub(crate) const fn new(store: &'a Store<P>, balance_source: &'a BeaconState<P>) -> Self {
        Self {
            store,
            balance_source,
        }
    }

    /// The store viewed.
    #[must_use]
    pub const fn store(&self) -> &'a Store<P> {
        self.store
    }

    /// The state whose validator set weighs the votes.
    #[must_use]
    pub const fn balance_source(&self) -> &'a BeaconState<P> {
        self.balance_source
    }

    /// The head of the chain.
    ///
    /// # Algorithm
    ///
    /// Start at the justified checkpoint's block.
    /// Repeatedly step to the heaviest viable child, until a block has none.
    /// Ties go to the larger root.
    ///
    /// See `get_head` in the phase0 fork choice spec.
    #[must_use]
    pub fn head(&self) -> Root {
        let weights = self.weights();
        let viable = self.viable_nodes();
        let mut head = self.store.checkpoints.justified().root;
        loop {
            let best = self
                .store
                .blocks
                .children(&head)
                .iter()
                .filter(|child| viable.contains(*child))
                .max_by_key(|child| (weights.get(*child).copied().unwrap_or_default(), **child));
            match best {
                Some(child) => head = *child,
                None => return head,
            }
        }
    }

    /// Leaves of the viable tree, each with its weight.
    ///
    /// Spec vectors check these to pin the weights, not just the winner.
    #[must_use]
    pub fn viable_leaves_and_weights(&self) -> Vec<(Root, Gwei)> {
        let weights = self.weights();
        let viable = self.viable_nodes();
        let blocks = &self.store.blocks;
        let mut leaves: Vec<(Root, Gwei)> = viable
            .iter()
            .filter(|root| {
                !blocks
                    .children(root)
                    .iter()
                    .any(|child| viable.contains(child))
            })
            .map(|root| (*root, weights.get(root).copied().unwrap_or_default()))
            .collect();
        leaves.sort();
        leaves
    }

    /// Weight of every block: the stake voting for it or a descendant, plus any proposer boost.
    ///
    /// # Algorithm
    ///
    /// Phase 1 credits each counted vote to the block it names.
    /// Phase 2 walks the tree children first, adding each subtree's weight into its parent.
    /// The result equals the spec's per-block sum, in one pass over votes and one over blocks.
    ///
    /// Take block a with children b and d, and c as the child of b:
    ///
    /// ```text
    /// votes:   a=0  b=10  c=20  d=5
    /// weights: a=35 b=30  c=20  d=5
    /// ```
    ///
    /// See `get_weight` in the phase0 fork choice spec.
    #[must_use]
    pub fn weights(&self) -> HashMap<Root, Gwei> {
        let mut weights = self.attestation_scores();

        // Proposer boost lifts the boosted block and every ancestor.
        let store = self.store;
        if store.proposer_boost_root != Root::ZERO {
            let boost = self.committee_fraction(store.config.proposer_score_boost);
            let mut current = Some(store.proposer_boost_root);
            while let Some(root) = current {
                let Some(node) = store.blocks.get(&root) else {
                    break;
                };
                *weights.entry(root).or_default() += boost;
                current = Some(node.parent_root);
            }
        }
        weights
    }

    /// Stake voting for each block or a descendant, in the balance source's validator set.
    ///
    /// Only active, unslashed validators with an uncontested latest vote count.
    /// See `get_attestation_score` in the phase0 fork choice spec.
    #[must_use]
    pub fn attestation_scores(&self) -> HashMap<Root, Gwei> {
        let state = self.balance_source;
        let store = self.store;
        let epoch = state.current_epoch();
        let mut weights: HashMap<Root, Gwei> = HashMap::new();

        // Phase 1: direct votes.
        for (index, validator) in state.validators.iter().enumerate() {
            if !validator.is_active_at(epoch) || validator.slashed {
                continue;
            }
            if let Some(message) = store.votes.counted(index.into())
                && store.blocks.contains(&message.root)
            {
                *weights.entry(message.root).or_default() += validator.effective_balance;
            }
        }

        // Phase 2: subtree sums, children before parents.
        // An invalid block passes no weight up, so votes for it support no valid ancestor.
        for (root, node) in store.blocks.iter().rev() {
            if node.status == ExecutionStatus::Invalid {
                continue;
            }
            let own = weights.get(root).copied().unwrap_or_default();
            if own != Gwei::ZERO && store.blocks.contains(&node.parent_root) {
                *weights.entry(node.parent_root).or_default() += own;
            }
        }
        weights
    }

    /// A share of one slot's committee weight in the balance source, as a percentage.
    ///
    /// Proposer boost and the reorg thresholds are expressed this way.
    #[must_use]
    pub fn committee_fraction(&self, percent: u64) -> Gwei {
        CommitteeWeight::of(self.balance_source).percent(percent)
    }

    /// Blocks of the justified subtree that lead to a viable leaf.
    ///
    /// A leaf is viable when its voting source agrees with the store's justified checkpoint,
    /// and it descends from the store's finalized checkpoint.
    /// An inner block is viable when any of its children is.
    ///
    /// See `filter_node_tree` in the phase0 fork choice spec.
    #[must_use]
    pub fn viable_nodes(&self) -> HashSet<Root> {
        let blocks = &self.store.blocks;

        // Depth-first order from the justified root, so reversing it visits children first.
        let mut order = Vec::new();
        let mut stack = vec![self.store.checkpoints.justified().root];
        while let Some(root) = stack.pop() {
            order.push(root);
            stack.extend_from_slice(blocks.children(&root));
        }

        let mut viable = HashSet::new();
        for root in order.into_iter().rev() {
            // An invalid payload removes the block and its subtree from consideration.
            if blocks
                .get(&root)
                .is_some_and(|node| node.status == ExecutionStatus::Invalid)
            {
                continue;
            }
            let children = blocks.children(&root);
            let is_viable = if children.is_empty() {
                self.is_viable_leaf(root)
            } else {
                children.iter().any(|child| viable.contains(child))
            };
            if is_viable {
                viable.insert(root);
            }
        }
        viable
    }

    /// Whether a leaf's checkpoints agree with the store's.
    fn is_viable_leaf(&self, root: Root) -> bool {
        let store = self.store;
        let current_epoch = store.current_epoch();
        let justified = store.checkpoints.justified();
        let finalized = store.checkpoints.finalized();
        let source = store.voting_source(root);

        // A source two epochs stale still counts, so the chain can recover from a late justification.
        let correct_justified = justified.epoch == Epoch::GENESIS
            || source.is_some_and(|source| {
                source.epoch == justified.epoch || source.epoch + 2 >= current_epoch
            });

        let correct_finalized = finalized.epoch == Epoch::GENESIS
            || store.checkpoint_block(root, finalized.epoch) == Some(finalized.root);

        correct_justified && correct_finalized
    }
}
