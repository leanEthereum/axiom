//! IWANT promises: peers that announced a message must deliver it once asked.

use std::{collections::BTreeMap, time::Duration};

use crate::{gossipsub::MessageId, identity::PeerId};

/// Delivery deadlines per message and peer.
///
/// A peer that announces a message in IHAVE and ignores the IWANT that follows breaks a promise.
/// See `libp2p/specs/pubsub/gossipsub/gossipsub-v1.1.md`, P7 behaviour penalty.
#[derive(Clone, Debug, Default)]
pub(super) struct Promises {
    /// Deadline per message and peer.
    deadlines: BTreeMap<MessageId, BTreeMap<PeerId, Duration>>,
}

impl Promises {
    /// Expects a peer to deliver a message by a deadline, keeping an earlier promise.
    pub(super) fn track(&mut self, id: MessageId, peer: &PeerId, deadline: Duration) {
        self.deadlines
            .entry(id)
            .or_default()
            .entry(peer.clone())
            .or_insert(deadline);
    }

    /// Releases every promise for a message, since some peer delivered it.
    pub(super) fn fulfil(&mut self, id: &MessageId) {
        self.deadlines.remove(id);
    }

    /// Drops the promises of a disconnected peer.
    pub(super) fn remove_peer(&mut self, peer: &PeerId) {
        for promised in self.deadlines.values_mut() {
            promised.remove(peer);
        }
    }

    /// Drops the promises past their deadline, returning one peer per broken promise.
    pub(super) fn expire(&mut self, now: Duration) -> Vec<PeerId> {
        let mut broken = Vec::new();
        self.deadlines.retain(|_, promised| {
            promised.retain(|peer, deadline| {
                if *deadline <= now {
                    broken.push(peer.clone());
                    return false;
                }
                true
            });
            !promised.is_empty()
        });
        broken
    }

    /// Number of messages with an outstanding promise.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.deadlines.len()
    }
}
