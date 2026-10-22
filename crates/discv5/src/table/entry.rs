//! One node in the routing table, with its liveness record.

use crate::{enr::Enr, node_id::NodeId};

/// Consecutive failed checks that evict a node that once answered.
///
/// UDP drops packets, so a proven node gets a few chances.
const VERIFIED_FAILURE_LIMIT: u8 = 3;

/// A known node and what the local node has seen of its liveness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The node's latest record.
    pub enr: Enr,
    /// Whether the node has ever answered a request.
    ///
    /// FINDNODE answers relay only verified nodes, per discv5-theory.md, "Table Maintenance".
    pub verified: bool,
    /// Requests in a row the node failed to answer.
    pub failures: u8,
}

impl Entry {
    /// A fresh, unverified entry.
    #[must_use]
    pub const fn new(enr: Enr) -> Self {
        Self {
            enr,
            verified: false,
            failures: 0,
        }
    }

    /// The node's identifier.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.enr.node_id()
    }

    /// Records an answer: the node is live.
    pub const fn record_success(&mut self) {
        self.verified = true;
        self.failures = 0;
    }

    /// Records a missed answer, returning whether the node should be evicted.
    pub const fn record_failure(&mut self) -> bool {
        // Threshold: unproven nodes go at once; proven ones after three misses in a row.
        self.failures = self.failures.saturating_add(1);
        !self.verified || self.failures >= VERIFIED_FAILURE_LIMIT
    }
}
