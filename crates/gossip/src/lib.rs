//! Gossip validation: which network messages a node accepts, ignores, or rejects.
//!
//! # Overview
//!
//! Gossipsub forwards a message only once the application has validated it.
//! Each rule of the consensus p2p spec ends in one of three outcomes.
//!
//! - Accept: the message is forwarded and processed.
//! - Ignore: the message is dropped, but its sender is not blamed.
//! - Reject: the message is dropped, and its sender's score falls.
//!
//! Rejection is reserved for messages no honest node would send.
//! Ignoring covers what an honest but slow or early node might send.
//!
//! See the `p2p-interface.md` specs from phase0 to Fulu, which define each rule as a function.

mod detail;
mod error;
mod seen;
mod signers;
mod signing_claim;
mod validator;
mod view;

pub use detail::Detail;
pub use error::GossipError;
pub use seen::Seen;
pub use validator::GossipValidator;
pub use view::ChainView;
