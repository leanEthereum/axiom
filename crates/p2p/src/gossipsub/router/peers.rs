//! The connected peers and what each one told the router.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use crate::{
    gossipsub::{MessageId, ProtocolVersion, Topic},
    identity::PeerId,
};

/// What the router knows about a connected peer.
#[derive(Clone, Debug)]
struct PeerState {
    /// The negotiated protocol revision.
    version: ProtocolVersion,
    /// Whether this node dialed the peer, which counts for the outbound quota.
    outbound: bool,
    /// Topics the peer subscribes to.
    topics: BTreeSet<Topic>,
    /// Messages the peer said it does not want, with the time each notice expires.
    dont_send: BTreeMap<MessageId, Duration>,
    /// IHAVE messages received this heartbeat.
    ihave_received: usize,
    /// Identifiers requested from the peer this heartbeat.
    iwant_asked: usize,
    /// IDONTWANT identifiers received this heartbeat.
    idontwant_received: usize,
}

/// The connected peers, their subscriptions, and their per-heartbeat budgets.
#[derive(Clone, Debug, Default)]
pub(super) struct Peers {
    /// State per connected peer.
    states: BTreeMap<PeerId, PeerState>,
}

impl Peers {
    /// Whether a peer is connected.
    pub(super) fn contains(&self, peer: &PeerId) -> bool {
        self.states.contains_key(peer)
    }

    /// Registers a peer, returning whether it was new.
    pub(super) fn insert(
        &mut self,
        peer: &PeerId,
        version: ProtocolVersion,
        outbound: bool,
    ) -> bool {
        if self.states.contains_key(peer) {
            return false;
        }
        self.states.insert(
            peer.clone(),
            PeerState {
                version,
                outbound,
                topics: BTreeSet::new(),
                dont_send: BTreeMap::new(),
                ihave_received: 0,
                iwant_asked: 0,
                idontwant_received: 0,
            },
        );
        true
    }

    /// Forgets a peer, returning whether it was connected.
    pub(super) fn remove(&mut self, peer: &PeerId) -> bool {
        self.states.remove(peer).is_some()
    }

    /// Updates the protocol revision of a peer.
    pub(super) fn set_version(&mut self, peer: &PeerId, version: ProtocolVersion) {
        if let Some(state) = self.states.get_mut(peer) {
            state.version = version;
        }
    }

    /// The protocol revision of a peer, the oldest one for an unknown peer.
    pub(super) fn version(&self, peer: &PeerId) -> ProtocolVersion {
        self.states
            .get(peer)
            .map_or(ProtocolVersion::V1_0, |state| state.version)
    }

    /// Whether this node dialed a peer.
    pub(super) fn is_outbound(&self, peer: &PeerId) -> bool {
        self.states.get(peer).is_some_and(|state| state.outbound)
    }

    /// Every connected peer.
    pub(super) fn ids(&self) -> impl Iterator<Item = &PeerId> {
        self.states.keys()
    }

    /// Connected peers subscribed to a topic.
    pub(super) fn topic_peers<'a>(&'a self, topic: &'a Topic) -> impl Iterator<Item = &'a PeerId> {
        self.states
            .iter()
            .filter(move |(_, state)| state.topics.contains(topic))
            .map(|(peer, _)| peer)
    }

    /// Whether a connected peer subscribes to a topic.
    pub(super) fn subscribes(&self, peer: &PeerId, topic: &Topic) -> bool {
        self.states
            .get(peer)
            .is_some_and(|state| state.topics.contains(topic))
    }

    /// Records a peer joining or leaving a topic, returning whether anything changed.
    pub(super) fn set_subscription(
        &mut self,
        peer: &PeerId,
        topic: &Topic,
        subscribe: bool,
    ) -> bool {
        let Some(state) = self.states.get_mut(peer) else {
            return false;
        };
        if subscribe {
            state.topics.insert(topic.clone())
        } else {
            state.topics.remove(topic)
        }
    }

    /// Whether a connected peer still wants a message, having sent no IDONTWANT for it.
    pub(super) fn wants(&self, peer: &PeerId, id: &MessageId) -> bool {
        self.states
            .get(peer)
            .is_some_and(|state| !state.dont_send.contains_key(id))
    }

    /// Counts an IHAVE from a peer, returning how many identifiers it may still be asked for.
    ///
    /// Nothing comes back for an unknown peer or one past either budget.
    pub(super) fn iwant_budget(
        &mut self,
        peer: &PeerId,
        max_messages: usize,
        max_length: usize,
    ) -> Option<usize> {
        let state = self.states.get_mut(peer)?;
        // Budget 1: IHAVE messages per heartbeat.
        state.ihave_received += 1;
        if state.ihave_received > max_messages || state.iwant_asked >= max_length {
            return None;
        }
        // Budget 2: identifiers requested per heartbeat.
        Some(max_length - state.iwant_asked)
    }

    /// Counts identifiers requested from a peer.
    pub(super) fn record_iwant(&mut self, peer: &PeerId, count: usize) {
        if let Some(state) = self.states.get_mut(peer) {
            state.iwant_asked += count;
        }
    }

    /// Records messages a peer does not want, within a per-heartbeat budget.
    pub(super) fn record_idontwant(
        &mut self,
        peer: &PeerId,
        ids: impl IntoIterator<Item = MessageId>,
        max: usize,
        expiry: Duration,
    ) {
        let Some(state) = self.states.get_mut(peer) else {
            return;
        };
        for id in ids {
            // Notices beyond the budget are ignored: honouring them only saves bandwidth.
            if state.idontwant_received >= max {
                return;
            }
            state.idontwant_received += 1;
            state.dont_send.insert(id, expiry);
        }
    }

    /// Resets the per-heartbeat budgets and drops expired IDONTWANT notices.
    pub(super) fn begin_heartbeat(&mut self, now: Duration) {
        for state in self.states.values_mut() {
            state.ihave_received = 0;
            state.iwant_asked = 0;
            state.idontwant_received = 0;
            state.dont_send.retain(|_, expiry| *expiry > now);
        }
    }
}
