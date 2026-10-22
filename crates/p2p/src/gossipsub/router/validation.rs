//! Messages held until the application decides on them.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use crate::{
    gossipsub::{MessageId, RawMessage},
    identity::PeerId,
};

/// A message waiting for the application's verdict.
#[derive(Clone, Debug)]
pub(super) struct Pending {
    /// The message.
    pub(super) message: RawMessage,
    /// The peer that delivered it first.
    pub(super) source: PeerId,
    /// Every peer that delivered it, who need not get it back.
    pub(super) seen_from: BTreeSet<PeerId>,
    /// When it arrived.
    received_at: Duration,
}

/// Messages awaiting validation, by identifier.
#[derive(Clone, Debug, Default)]
pub(super) struct Validations {
    /// The held messages.
    pending: BTreeMap<MessageId, Pending>,
}

impl Validations {
    /// Holds a message first delivered by a peer.
    pub(super) fn hold(
        &mut self,
        id: MessageId,
        message: RawMessage,
        source: &PeerId,
        now: Duration,
    ) {
        self.pending.insert(
            id,
            Pending {
                message,
                source: source.clone(),
                seen_from: BTreeSet::from([source.clone()]),
                received_at: now,
            },
        );
    }

    /// Notes another peer delivering a held message.
    pub(super) fn note_duplicate(&mut self, id: &MessageId, from: &PeerId) {
        if let Some(pending) = self.pending.get_mut(id) {
            pending.seen_from.insert(from.clone());
        }
    }

    /// Releases a held message for its verdict.
    pub(super) fn take(&mut self, id: &MessageId) -> Option<Pending> {
        self.pending.remove(id)
    }

    /// Messages held for at least the timeout.
    pub(super) fn stale(&self, now: Duration, timeout: Duration) -> Vec<MessageId> {
        self.pending
            .iter()
            .filter(|(_, pending)| now.saturating_sub(pending.received_at) >= timeout)
            .map(|(id, _)| *id)
            .collect()
    }
}
