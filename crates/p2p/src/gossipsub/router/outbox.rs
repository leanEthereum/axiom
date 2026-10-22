//! RPCs waiting to leave the router.

use std::collections::{BTreeMap, VecDeque};

use crate::{
    gossipsub::{ControlMessage, RawMessage, Rpc, SubOpts},
    identity::PeerId,
};

/// RPCs waiting to be sent: full messages one per RPC, control merged per peer.
#[derive(Clone, Debug, Default)]
pub(super) struct Outbox {
    /// Messages to send, one per RPC, in order.
    messages: VecDeque<(PeerId, Rpc)>,
    /// Subscriptions and control to send, merged per peer.
    control: BTreeMap<PeerId, Rpc>,
}

impl Outbox {
    /// The next RPC to send, and its recipient.
    pub(super) fn poll(&mut self) -> Option<(PeerId, Rpc)> {
        // Full messages first: they carry the latency-critical payloads.
        if let Some(next) = self.messages.pop_front() {
            return Some(next);
        }
        self.control.pop_first()
    }

    /// Queues one full message for a peer.
    pub(super) fn send_message(&mut self, peer: PeerId, message: RawMessage) {
        self.send_now(
            peer,
            Rpc {
                publish: vec![message],
                ..Rpc::default()
            },
        );
    }

    /// Queues an RPC alongside full messages, ahead of the batched control.
    pub(super) fn send_now(&mut self, peer: PeerId, rpc: Rpc) {
        self.messages.push_back((peer, rpc));
    }

    /// Queues a subscription change for a peer.
    pub(super) fn subscription(&mut self, peer: &PeerId, subscription: SubOpts) {
        self.control
            .entry(peer.clone())
            .or_default()
            .subscriptions
            .push(subscription);
    }

    /// The pending control message of a peer, created on first use.
    pub(super) fn control(&mut self, peer: &PeerId) -> &mut ControlMessage {
        self.control
            .entry(peer.clone())
            .or_default()
            .control
            .get_or_insert_with(ControlMessage::default)
    }

    /// Drops everything queued for a peer.
    pub(super) fn remove_peer(&mut self, peer: &PeerId) {
        self.control.remove(peer);
        self.messages.retain(|(recipient, _)| recipient != peer);
    }
}
