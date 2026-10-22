//! The Ethereum consensus p2p domains: gossip topics and encoding, and req/resp.
//!
//! See `specs/phase0/p2p-interface.md` and its successors through Fulu.

mod gossip;
mod message_id;
pub mod reqresp;
mod topic;

pub use gossip::{
    GossipDecodeError, GossipEncoding, MAX_PAYLOAD_SIZE, MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
};
pub use message_id::MessageIds;
pub use topic::{GossipKind, GossipTopic, TopicError};
