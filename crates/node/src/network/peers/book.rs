//! The peers the node has met, published for readers outside the network task.

use std::{collections::BTreeMap, sync::Arc};

use axiom_p2p::{Multiaddr, PeerId};
use tokio::sync::watch;

/// Disconnected peers remembered, oldest forgotten first.
///
/// The bound keeps a churning peer set from growing the table without limit.
const REMEMBERED_DISCONNECTED: usize = 256;

/// One peer, as the node routes report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerRecord {
    /// The libp2p peer identifier, in text.
    pub(crate) peer_id: String,
    /// The address the peer was last seen at.
    pub(crate) address: String,
    /// Whether this node dialed the peer.
    pub(crate) outbound: bool,
    /// Whether the connection is open.
    pub(crate) connected: bool,
}

/// The peers the network task tracks, and the snapshot it publishes after each change.
///
/// Readers get an immutable snapshot through a watch channel.
/// The network task never waits on them, and they never see a half-made change.
#[derive(Debug)]
pub(crate) struct PeerBook {
    /// Every remembered peer.
    records: BTreeMap<PeerId, PeerRecord>,
    /// Disconnected peers in the order they left.
    departed: Vec<PeerId>,
    /// The published snapshot.
    published: watch::Sender<Arc<Vec<PeerRecord>>>,
}

impl PeerBook {
    /// An empty book and a reader of its snapshots.
    pub(crate) fn new() -> (Self, watch::Receiver<Arc<Vec<PeerRecord>>>) {
        let (published, reader) = watch::channel(Arc::new(Vec::new()));
        let book = Self {
            records: BTreeMap::new(),
            departed: Vec::new(),
            published,
        };
        (book, reader)
    }

    /// Records an opened connection.
    pub(crate) fn connected(&mut self, peer: &PeerId, address: &Multiaddr, outbound: bool) {
        self.departed.retain(|departed| departed != peer);
        self.records.insert(
            peer.clone(),
            PeerRecord {
                peer_id: peer.to_string(),
                address: address.to_string(),
                outbound,
                connected: true,
            },
        );
        self.publish();
    }

    /// Records a closed connection, forgetting the oldest departure past the bound.
    pub(crate) fn disconnected(&mut self, peer: &PeerId) {
        let Some(record) = self.records.get_mut(peer) else {
            return;
        };
        record.connected = false;
        self.departed.push(peer.clone());
        if self.departed.len() > REMEMBERED_DISCONNECTED {
            let oldest = self.departed.remove(0);
            self.records.remove(&oldest);
        }
        self.publish();
    }

    /// Replaces the published snapshot.
    fn publish(&self) {
        let snapshot: Vec<PeerRecord> = self.records.values().cloned().collect();
        // Readers may all have gone, which leaves nothing to tell.
        self.published.send_replace(Arc::new(snapshot));
    }
}
