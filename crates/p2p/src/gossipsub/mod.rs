//! Gossipsub v1.0, v1.1, and v1.2: topic-based publish and subscribe over a sparse mesh.
//!
//! # Overview
//!
//! Each node keeps, per topic, a mesh of about D peers that receive full messages.
//! Other topic peers hear only identifiers, through periodic IHAVE gossip.
//!
//! Messages spread in two ways:
//!
//! - Eager push: the publisher sends the full message to its mesh peers, which forward it to theirs.
//! - Lazy pull: the publisher sends IHAVE with identifiers to a non-mesh peer.
//! - That peer answers IWANT for an identifier it lacks, and receives the full message.
//!
//! The heartbeat keeps each mesh between D_low and D_high with GRAFT and PRUNE.
//! v1.1 adds backoff, peer exchange, flood publishing, and peer scoring.
//! v1.2 adds IDONTWANT, so mesh peers skip sending a large message twice.
//!
//! Ethereum runs gossipsub with StrictNoSign and content-derived 20-byte identifiers.
//! See `libp2p/specs/pubsub/gossipsub` and `specs/phase0/p2p-interface.md`.

mod config;
mod mcache;
mod router;
mod rpc;
pub mod score;
mod seen;
mod types;

pub use config::GossipsubConfig;
pub use router::{GossipsubEvent, PublishError, Router};
pub use rpc::{
    ControlMessage, Graft, IDontWant, IHave, IWant, PeerInfo, Prune, RawMessage, Rpc, SubOpts,
};
pub use score::{PeerScore, PeerScoreParams, PeerScoreThresholds, TopicScoreParams};
pub use types::{MESSAGE_ID_LEN, MessageId, ProtocolVersion, Topic, ValidationOutcome};
