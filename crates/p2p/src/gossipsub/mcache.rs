//! The message cache: full recent messages, in heartbeat windows.
//!
//! ```text
//! windows:   [ newest ][ w1 ][ w2 ][ w3 ][ w4 ][ oldest ]   history_length = 6
//!            └──── gossiped in IHAVE ────┘                 history_gossip = 3
//!
//! every heartbeat: drop the oldest window, open a new empty one
//! ```
//!
//! See the message cache section of gossipsub v1.0.

use std::collections::{BTreeMap, VecDeque};

use super::{MessageId, RawMessage, Topic};
use crate::identity::PeerId;

/// One cached message and how often each peer asked for it.
#[derive(Clone, Debug)]
struct Entry {
    /// The message.
    message: RawMessage,
    /// IWANT answers sent per peer.
    requests: BTreeMap<PeerId, usize>,
}

/// Recent messages, kept for IWANT answers and IHAVE gossip.
#[derive(Clone, Debug)]
pub(super) struct MessageCache {
    /// Messages by identifier.
    entries: BTreeMap<MessageId, Entry>,
    /// Identifiers per heartbeat window, newest first.
    windows: VecDeque<Vec<(MessageId, Topic)>>,
    /// Windows announced in gossip.
    gossip_windows: usize,
}

impl MessageCache {
    /// A cache of a number of windows, the newest few of them gossiped.
    pub(super) fn new(history_length: usize, history_gossip: usize) -> Self {
        let mut windows = VecDeque::with_capacity(history_length);
        windows.resize_with(history_length.max(1), Vec::new);
        Self {
            entries: BTreeMap::new(),
            windows,
            gossip_windows: history_gossip,
        }
    }

    /// Adds a validated message to the newest window.
    pub(super) fn put(&mut self, id: MessageId, message: RawMessage) {
        if self.entries.contains_key(&id) {
            return;
        }
        let topic = message.topic.clone();
        self.entries.insert(
            id,
            Entry {
                message,
                requests: BTreeMap::new(),
            },
        );
        if let Some(newest) = self.windows.front_mut() {
            newest.push((id, topic));
        }
    }

    /// A cached message for an IWANT answer, counting the peer's request.
    ///
    /// # Returns
    ///
    /// The message and how many times this peer has now asked for it.
    pub(super) fn get_for_peer(
        &mut self,
        id: &MessageId,
        peer: &PeerId,
    ) -> Option<(&RawMessage, usize)> {
        let entry = self.entries.get_mut(id)?;
        let count = entry.requests.entry(peer.clone()).or_insert(0);
        *count += 1;
        Some((&entry.message, *count))
    }

    /// Identifiers of a topic in the gossiped windows.
    pub(super) fn gossip_ids(&self, topic: &Topic) -> Vec<MessageId> {
        self.windows
            .iter()
            .take(self.gossip_windows)
            .flatten()
            .filter(|(_, t)| t == topic)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Slides the windows: the oldest is dropped, a fresh one opens.
    pub(super) fn shift(&mut self) {
        if let Some(oldest) = self.windows.pop_back() {
            for (id, _) in oldest {
                self.entries.remove(&id);
            }
        }
        self.windows.push_front(Vec::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PublicKey;

    #[test]
    fn windows_slide() {
        // Fixture state: 3 windows, the newest 2 gossiped.
        let mut cache = MessageCache::new(3, 2);
        let topic = Topic::new("t");
        let message = RawMessage::anonymous(topic.clone(), vec![1]);
        let id = MessageId([1; 20]);

        // Put at window 0: gossiped.
        cache.put(id, message);
        assert_eq!(cache.gossip_ids(&topic), [id]);
        // After one shift it sits in window 1: still gossiped.
        cache.shift();
        assert_eq!(cache.gossip_ids(&topic), [id]);
        // After two shifts, window 2: cached but no longer announced.
        cache.shift();
        assert!(cache.gossip_ids(&topic).is_empty());
        let peer = PeerId::from_public_key(&PublicKey::secp256k1([2; 33]));
        assert!(cache.get_for_peer(&id, &peer).is_some());
        // After three shifts it falls off the end.
        cache.shift();
        assert!(cache.get_for_peer(&id, &peer).is_none());
    }

    #[test]
    fn counts_requests_per_peer() {
        let mut cache = MessageCache::new(3, 2);
        let id = MessageId([2; 20]);
        cache.put(id, RawMessage::anonymous(Topic::new("t"), vec![]));
        let peer = PeerId::from_public_key(&PublicKey::secp256k1([2; 33]));
        // Each IWANT answer for the same peer increments its count.
        assert_eq!(cache.get_for_peer(&id, &peer).map(|(_, n)| n), Some(1));
        assert_eq!(cache.get_for_peer(&id, &peer).map(|(_, n)| n), Some(2));
    }
}
