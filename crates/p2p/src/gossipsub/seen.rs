//! The seen cache: identifiers of recent messages, for duplicate suppression.

use std::{
    collections::{BTreeSet, VecDeque},
    time::Duration,
};

use super::MessageId;

/// Identifiers seen within a time window.
///
/// Insertions arrive in time order, so expiry pops from the front of a queue.
#[derive(Clone, Debug)]
pub(super) struct SeenCache {
    /// How long an identifier stays.
    ttl: Duration,
    /// Identifiers present.
    ids: BTreeSet<MessageId>,
    /// Insertion times, oldest first.
    queue: VecDeque<(Duration, MessageId)>,
}

impl SeenCache {
    /// An empty cache with a lifetime.
    pub(super) const fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ids: BTreeSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// Records an identifier, returning whether it was new.
    pub(super) fn insert(&mut self, id: MessageId, now: Duration) -> bool {
        self.expire(now);
        if !self.ids.insert(id) {
            return false;
        }
        self.queue.push_back((now, id));
        true
    }

    /// Whether an identifier was seen within the window.
    pub(super) fn contains(&self, id: &MessageId) -> bool {
        self.ids.contains(id)
    }

    /// Forgets identifiers older than the window.
    pub(super) fn expire(&mut self, now: Duration) {
        while let Some(&(at, id)) = self.queue.front() {
            // Timing: an entry inserted at t lives until t + ttl.
            if at + self.ttl > now {
                break;
            }
            self.queue.pop_front();
            self.ids.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_after_ttl() {
        // Fixture state: a 10 s window.
        let mut cache = SeenCache::new(Duration::from_secs(10));
        let id = MessageId([1; 20]);
        // First sighting at t = 0 is new; a second at t = 5 is a duplicate.
        assert!(cache.insert(id, Duration::ZERO));
        assert!(!cache.insert(id, Duration::from_secs(5)));
        // At t = 10 the entry from t = 0 is gone, so the message is new again.
        cache.expire(Duration::from_secs(10));
        assert!(!cache.contains(&id));
        assert!(cache.insert(id, Duration::from_secs(10)));
    }
}
