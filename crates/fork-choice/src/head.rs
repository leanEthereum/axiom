//! LMD-GHOST head selection over the viable part of the block tree.

use std::collections::{HashMap, HashSet};

use axiom_types::{BeaconState, Checkpoint, Epoch, Gwei, Preset, Root};

use crate::{ForkChoiceError, Store};

impl<P: Preset> Store<P> {
    /// The head of the chain.
    ///
    /// # Algorithm
    ///
    /// Start at the justified checkpoint's block.
    /// Repeatedly step to the heaviest viable child, until a block has none.
    /// Ties go to the larger root.
    ///
    /// See `get_head` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn head(&mut self) -> Result<Root, ForkChoiceError> {
        let weights = self.weights()?;
        let viable = self.viable_nodes();
        let mut head = self.justified_checkpoint.root;
        loop {
            let best = self
                .blocks
                .children(&head)
                .iter()
                .filter(|child| viable.contains(*child))
                .max_by_key(|child| (weights.get(*child).copied().unwrap_or_default(), **child));
            match best {
                Some(child) => head = *child,
                None => return Ok(head),
            }
        }
    }

    /// Leaves of the viable tree, each with its weight.
    ///
    /// Spec vectors check these to pin the weights, not just the winner.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn viable_leaves_and_weights(&mut self) -> Result<Vec<(Root, Gwei)>, ForkChoiceError> {
        let weights = self.weights()?;
        let viable = self.viable_nodes();
        let mut leaves: Vec<(Root, Gwei)> = viable
            .iter()
            .filter(|root| {
                !self
                    .blocks
                    .children(root)
                    .iter()
                    .any(|child| viable.contains(child))
            })
            .map(|root| (*root, weights.get(root).copied().unwrap_or_default()))
            .collect();
        leaves.sort();
        Ok(leaves)
    }

    /// Weight of every block: the stake voting for it or a descendant, plus any proposer boost.
    ///
    /// # Algorithm
    ///
    /// Phase 1 credits each counted vote to the block it names.
    /// Phase 2 walks the tree children first, adding each subtree's weight into its parent.
    /// The result equals the spec's per-block sum, in one pass over votes and one over blocks.
    ///
    /// ```text
    /// votes:   a=0  b=10  c=20  d=5          a -> b -> c
    /// weights: a=35 b=30  c=20  d=5            \
    ///                                           d
    /// ```
    ///
    /// See `get_weight` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the justified checkpoint's state is missing.
    pub fn weights(&mut self) -> Result<HashMap<Root, Gwei>, ForkChoiceError> {
        let justified = self.justified_checkpoint;
        let justified_state = self.checkpoint_state(justified)?.beacon().clone();

        let mut weights = self.attestation_scores(&justified_state);

        // Proposer boost lifts the boosted block and every ancestor.
        if self.proposer_boost_root != Root::ZERO {
            let boost =
                Self::committee_fraction(&justified_state, self.config.proposer_score_boost);
            let mut current = Some(self.proposer_boost_root);
            while let Some(root) = current {
                let Some(node) = self.blocks.get(&root) else {
                    break;
                };
                *weights.entry(root).or_default() += boost;
                current = Some(node.parent_root);
            }
        }
        Ok(weights)
    }

    /// Stake voting for each block or a descendant, in a state's validator set.
    ///
    /// Only active, unslashed validators with an uncontested latest vote count.
    /// See `get_attestation_score` in the phase0 fork choice spec.
    #[must_use]
    pub fn attestation_scores(&self, state: &BeaconState<P>) -> HashMap<Root, Gwei> {
        let epoch = state.current_epoch();
        let mut weights: HashMap<Root, Gwei> = HashMap::new();

        // Phase 1: direct votes.
        for (index, validator) in state.validators.iter().enumerate() {
            if !validator.is_active_at(epoch) || validator.slashed {
                continue;
            }
            if let Some(message) = self.votes.counted(index.into())
                && self.blocks.contains(&message.root)
            {
                *weights.entry(message.root).or_default() += validator.effective_balance;
            }
        }

        // Phase 2: subtree sums, children before parents.
        for (root, node) in self.blocks.iter().rev() {
            let own = weights.get(root).copied().unwrap_or_default();
            if own != Gwei::ZERO && self.blocks.contains(&node.parent_root) {
                *weights.entry(node.parent_root).or_default() += own;
            }
        }
        weights
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
        // Depth-first order from the justified root, so reversing it visits children first.
        let mut order = Vec::new();
        let mut stack = vec![self.justified_checkpoint.root];
        while let Some(root) = stack.pop() {
            order.push(root);
            stack.extend_from_slice(self.blocks.children(&root));
        }

        let mut viable = HashSet::new();
        for root in order.into_iter().rev() {
            let children = self.blocks.children(&root);
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
        let current_epoch = self.current_epoch();
        let source = self.voting_source(root);

        // A source two epochs stale still counts, so the chain can recover from a late justification.
        let correct_justified = self.justified_checkpoint.epoch == Epoch::GENESIS
            || source.is_some_and(|source| {
                source.epoch == self.justified_checkpoint.epoch || source.epoch + 2 >= current_epoch
            });

        let correct_finalized = self.finalized_checkpoint.epoch == Epoch::GENESIS
            || self.checkpoint_block(root, self.finalized_checkpoint.epoch)
                == Some(self.finalized_checkpoint.root);

        correct_justified && correct_finalized
    }

    /// The justified checkpoint a block would vote with as the head.
    ///
    /// A block from a past epoch is pulled up: its unrealized justification counts.
    /// See `get_voting_source` in the phase0 fork choice spec.
    #[must_use]
    pub fn voting_source(&self, root: Root) -> Option<Checkpoint> {
        let node = self.blocks.get(&root)?;
        if self.current_epoch() > node.slot.epoch::<P>() {
            self.unrealized_justifications.get(&root).copied()
        } else {
            self.block_states
                .get(&root)
                .map(|state| state.beacon().current_justified_checkpoint)
        }
    }
}
