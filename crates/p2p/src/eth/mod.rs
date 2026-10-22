//! The Ethereum consensus p2p domains: gossip topics and encoding, and req/resp.
//!
//! See `specs/phase0/p2p-interface.md` and its successors through Fulu.

mod gossip;
pub mod reqresp;
mod topic;

pub use gossip::{
    GossipDecodeError, MAX_PAYLOAD_SIZE, MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY, decode_gossip, encode_gossip, gossip_message_id,
    max_compressed_len, max_message_size,
};
pub use topic::{GossipKind, GossipTopic, TopicError};
