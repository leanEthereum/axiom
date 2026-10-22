//! One block of the weight tree: its place in the tree, and the scores of its three nodes.

use std::{mem, ops::AddAssign};

use axiom_types::{Gwei, Root, Slot};

use crate::{NodePayload, PayloadArrival};

/// One value for each fork choice node of a block: its empty, full, and pending variants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PerNode<T> {
    /// The value of the empty variant.
    pub(crate) empty: T,
    /// The value of the full variant.
    pub(crate) full: T,
    /// The value of the pending node.
    pub(crate) pending: T,
}

impl<T> PerNode<T> {
    /// The value of one node.
    pub(crate) const fn get(&self, payload: NodePayload) -> &T {
        match payload {
            NodePayload::Empty => &self.empty,
            NodePayload::Full => &self.full,
            NodePayload::Pending => &self.pending,
        }
    }

    /// The value of one node, for an edit.
    pub(crate) const fn get_mut(&mut self, payload: NodePayload) -> &mut T {
        match payload {
            NodePayload::Empty => &mut self.empty,
            NodePayload::Full => &mut self.full,
            NodePayload::Pending => &mut self.pending,
        }
    }
}

/// Stake added to and removed from a score since the score was last settled.
///
/// Two unsigned halves keep every intermediate in range without signed arithmetic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Change {
    /// Stake added.
    pub(crate) added: Gwei,
    /// Stake removed.
    pub(crate) removed: Gwei,
}

impl Change {
    /// A change that only adds.
    pub(crate) const fn adding(stake: Gwei) -> Self {
        Self {
            added: stake,
            removed: Gwei::ZERO,
        }
    }

    /// A change that only removes.
    pub(crate) const fn removing(stake: Gwei) -> Self {
        Self {
            added: Gwei::ZERO,
            removed: stake,
        }
    }

    /// The score after the change.
    ///
    /// Invariant: every removal undoes an earlier addition to the same score.
    /// So the removed stake never exceeds the score plus the added stake.
    pub(crate) fn settle(self, score: Gwei) -> Gwei {
        score + self.added - self.removed
    }
}

impl AddAssign for Change {
    fn add_assign(&mut self, other: Self) {
        self.added += other.added;
        self.removed += other.removed;
    }
}

/// What the weight tree keeps of a block.
///
/// The tree fields mirror the block tree.
/// The scores are the attestation scores of the block's three nodes, without proposer boost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TreeNode {
    /// The block's root.
    pub(crate) root: Root,
    /// Position of the parent, or nothing for a block whose parent is outside the tree.
    pub(crate) parent: Option<usize>,
    /// The variant of the parent the block builds on, empty or full.
    pub(crate) parent_payload: NodePayload,
    /// Slot of the block.
    pub(crate) slot: Slot,
    /// Where the block's payload is.
    pub(crate) arrival: PayloadArrival,
    /// Whether the execution engine found the block's payload invalid.
    pub(crate) invalid: bool,
    /// Children building on each variant, of any validity; the pending entry stays zero.
    pub(crate) children: PerNode<u32>,
    /// Stake whose supported node is each node or a descendant of it.
    pub(crate) scores: PerNode<Gwei>,
    /// Changes to the scores not yet settled.
    changes: PerNode<Change>,
    /// Whether the parent's scores hold this block's pending score.
    passed_up: bool,
}

impl TreeNode {
    /// A block with no stake yet.
    pub(crate) fn new(
        root: Root,
        parent: Option<usize>,
        parent_payload: NodePayload,
        slot: Slot,
        arrival: PayloadArrival,
        invalid: bool,
    ) -> Self {
        Self {
            root,
            parent,
            parent_payload,
            slot,
            arrival,
            invalid,
            children: PerNode::default(),
            scores: PerNode::default(),
            changes: PerNode::default(),
            // A zero score is held by the parent either way, so the block starts as passed up.
            passed_up: true,
        }
    }

    /// Whether the block has children building on a variant.
    pub(crate) const fn has_children(&self, payload: NodePayload) -> bool {
        *self.children.get(payload) > 0
    }

    /// Records a change to the stake supporting one of the block's nodes directly.
    pub(crate) fn change(&mut self, payload: NodePayload, change: Change) {
        *self.changes.get_mut(payload) += change;
    }

    /// Settles the pending changes, returning the change the parent's scores need.
    ///
    /// The pending node sums both variants, so their changes reach it too.
    /// An invalid block passes nothing up: its whole score leaves the parent once.
    pub(crate) fn settle(&mut self) -> Change {
        let changes = mem::take(&mut self.changes);
        let mut pending = changes.pending;
        pending += changes.empty;
        pending += changes.full;

        let before = self.scores.pending;
        self.scores.empty = changes.empty.settle(self.scores.empty);
        self.scores.full = changes.full.settle(self.scores.full);
        self.scores.pending = pending.settle(before);

        let passes_up = !self.invalid;
        let up = match (self.passed_up, passes_up) {
            (true, true) => pending,
            (false, true) => Change::adding(self.scores.pending),
            (true, false) => Change::removing(before),
            (false, false) => Change::default(),
        };
        self.passed_up = passes_up;
        up
    }
}
