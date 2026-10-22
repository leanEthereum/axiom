//! Graft backoffs: how long a pruned peer stays out of a mesh.

use std::{collections::BTreeMap, time::Duration};

use crate::{gossipsub::Topic, identity::PeerId};

/// Graft backoffs per topic and peer, with their expiry.
///
/// Both sides of a PRUNE wait out the backoff before regrafting.
/// See `libp2p/specs/pubsub/gossipsub/gossipsub-v1.1.md`, PRUNE backoff.
#[derive(Clone, Debug, Default)]
pub(super) struct Backoffs {
    /// Expiry per topic and peer.
    expiries: BTreeMap<(Topic, PeerId), Duration>,
}

impl Backoffs {
    /// When the backoff of a peer in a topic expires, if one was ever set.
    pub(super) fn expiry(&self, topic: &Topic, peer: &PeerId) -> Option<Duration> {
        self.expiries.get(&(topic.clone(), peer.clone())).copied()
    }

    /// Whether a peer may not be grafted to a topic yet.
    pub(super) fn is_active(&self, topic: &Topic, peer: &PeerId, now: Duration) -> bool {
        self.expiry(topic, peer).is_some_and(|expiry| expiry > now)
    }

    /// Starts a backoff, replacing any earlier one.
    pub(super) fn start(&mut self, topic: &Topic, peer: &PeerId, expiry: Duration) {
        self.expiries.insert((topic.clone(), peer.clone()), expiry);
    }

    /// Extends a backoff to an expiry, never shortening it.
    pub(super) fn extend(&mut self, topic: &Topic, peer: &PeerId, expiry: Duration) {
        let entry = self
            .expiries
            .entry((topic.clone(), peer.clone()))
            .or_insert(expiry);
        *entry = (*entry).max(expiry);
    }

    /// Drops the backoffs that have run out.
    pub(super) fn expire(&mut self, now: Duration) {
        self.expiries.retain(|_, expiry| *expiry > now);
    }
}
