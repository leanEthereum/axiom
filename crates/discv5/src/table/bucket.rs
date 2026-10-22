//! One k-bucket: up to k nodes ordered by last contact, and one pending candidate.

use std::time::Duration;

use super::Entry;
use crate::node_id::NodeId;

/// A candidate waiting for a full bucket's stalest node to fail its liveness check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The candidate.
    pub entry: Entry,
    /// When the candidate gives up waiting.
    pub deadline: Duration,
}

/// Nodes at one logarithmic distance, least recently seen first.
///
/// # Overview
///
/// ```text
/// entries: [stalest, ..., freshest]      at most k
/// pending: a newcomer that found the bucket full
/// ```
///
/// A full bucket keeps its old nodes: long-lived nodes tend to stay up.
/// The newcomer replaces the stalest node only if that node fails a check.
/// See discv5-theory.md, "Node Table".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KBucket {
    /// Entries, least recently seen first.
    entries: Vec<Entry>,
    /// The newcomer waiting on the stalest entry, if any.
    pending: Option<Pending>,
}

impl KBucket {
    /// The entries, least recently seen first.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The pending candidate.
    #[must_use]
    pub const fn pending(&self) -> Option<&Pending> {
        self.pending.as_ref()
    }

    /// Entries held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the bucket is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The position of a node.
    pub(crate) fn position(&self, node: &NodeId) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.node_id() == *node)
    }

    /// The entry of a node.
    pub(crate) fn get(&self, node: &NodeId) -> Option<&Entry> {
        self.position(node).map(|index| &self.entries[index])
    }

    /// The entry of a node, mutably.
    pub(crate) fn get_mut(&mut self, node: &NodeId) -> Option<&mut Entry> {
        self.position(node).map(|index| &mut self.entries[index])
    }

    /// Appends an entry as the most recently seen.
    pub(crate) fn push(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Moves a node to the most recently seen end.
    pub(crate) fn touch(&mut self, node: &NodeId) {
        // Rotate the entry to the tail, keeping the others in order.
        if let Some(index) = self.position(node) {
            self.entries[index..].rotate_left(1);
        }
    }

    /// Removes a node, returning its entry.
    pub(crate) fn remove(&mut self, node: &NodeId) -> Option<Entry> {
        self.position(node).map(|index| self.entries.remove(index))
    }

    /// Sets the pending candidate.
    pub(crate) fn set_pending(&mut self, pending: Pending) {
        self.pending = Some(pending);
    }

    /// Takes the pending candidate out.
    pub(crate) const fn take_pending(&mut self) -> Option<Pending> {
        self.pending.take()
    }

    /// The stalest entry, the one a newcomer challenges.
    #[must_use]
    pub fn stalest(&self) -> Option<&Entry> {
        self.entries.first()
    }
}
