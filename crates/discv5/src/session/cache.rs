//! The bounded, least-recently-used store of sessions.

use std::{collections::BTreeMap, net::SocketAddr};

use super::Session;
use crate::node_id::NodeId;

/// Sessions keyed by node id and UDP endpoint, evicting the least recently used.
///
/// The endpoint is part of the key so a spoofed source address never reaches a session.
/// See discv5-theory.md, "Session Cache".
#[derive(Debug)]
pub struct SessionCache {
    /// Most sessions kept at once.
    capacity: usize,
    /// Sessions with the tick of their last use.
    entries: BTreeMap<(NodeId, SocketAddr), (Session, u64)>,
    /// A counter that orders uses.
    tick: u64,
}

impl SessionCache {
    /// An empty cache holding up to a given number of sessions.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            tick: 0,
        }
    }

    /// The session with a peer at an endpoint, marked as just used.
    pub fn get_mut(&mut self, node: NodeId, addr: SocketAddr) -> Option<&mut Session> {
        // Every access refreshes the entry's place in the eviction order.
        self.tick += 1;
        let tick = self.tick;
        self.entries.get_mut(&(node, addr)).map(|(session, used)| {
            *used = tick;
            session
        })
    }

    /// The session with a peer at an endpoint, without touching its use time.
    #[must_use]
    pub fn get(&self, node: NodeId, addr: SocketAddr) -> Option<&Session> {
        self.entries.get(&(node, addr)).map(|(session, _)| session)
    }

    /// Whether a session exists, without touching its use time.
    #[must_use]
    pub fn contains(&self, node: NodeId, addr: SocketAddr) -> bool {
        self.entries.contains_key(&(node, addr))
    }

    /// Stores a session, replacing any earlier one and evicting the stalest when full.
    pub fn insert(&mut self, node: NodeId, addr: SocketAddr, session: Session) {
        // Threshold: at capacity, a new key pushes out the least recently used.
        let key = (node, addr);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let stalest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| *key);
            if let Some(stalest) = stalest {
                self.entries.remove(&stalest);
            }
        }
        self.tick += 1;
        self.entries.insert(key, (session, self.tick));
    }

    /// Drops the session with a peer at an endpoint.
    pub fn remove(&mut self, node: NodeId, addr: SocketAddr) {
        self.entries.remove(&(node, addr));
    }

    /// Sessions held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no session is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_the_least_recently_used() {
        // Fixture state: a cache of two, with sessions for nodes 1 and 2.
        let addr: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let session = Session::new(&[1; 16], &[2; 16]);
        let mut cache = SessionCache::new(2);
        cache.insert(NodeId([1; 32]), addr, session.clone());
        cache.insert(NodeId([2; 32]), addr, session.clone());
        // Touching node 1 makes node 2 the stalest.
        assert!(cache.get_mut(NodeId([1; 32]), addr).is_some());
        cache.insert(NodeId([3; 32]), addr, session);
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(NodeId([1; 32]), addr));
        assert!(!cache.contains(NodeId([2; 32]), addr));
        assert!(cache.contains(NodeId([3; 32]), addr));
        // Another endpoint for node 1 is another key.
        let moved: SocketAddr = "10.0.0.2:9000".parse().unwrap();
        assert!(cache.get_mut(NodeId([1; 32]), moved).is_none());
    }
}
