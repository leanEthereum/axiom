//! The state every part of the router reads and writes.

use super::{outbox::Outbox, peers::Peers, scorer::Scorer};
use crate::{gossipsub::GossipsubConfig, rng::Rng};

/// The state the mesh, the fanout, and gossip share.
///
/// Each part owns its own tables and borrows this for everything else.
#[derive(Debug)]
pub(super) struct Context {
    /// Parameters.
    pub(super) config: GossipsubConfig,
    /// Randomness for peer selection.
    pub(super) rng: Rng,
    /// Connected peers.
    pub(super) peers: Peers,
    /// Peer scoring, possibly disabled.
    pub(super) scorer: Scorer,
    /// RPCs to send.
    pub(super) outbox: Outbox,
}
