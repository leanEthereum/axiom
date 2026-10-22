//! The libp2p protocol stack, and the Ethereum consensus domains built on it.
//!
//! # Overview
//!
//! Every protocol is a pure state machine first: bytes and time go in, bytes and events come out.
//! Thin tokio adapters then drive those machines over real sockets.
//!
//! The node sends commands to the swarm and receives events from it.
//! The swarm runs on tokio and hosts the gossipsub router, the req/resp codec, identify, and ping.
//!
//! Below the swarm, the stack has four layers, top to bottom:
//!
//! 1. Yamux streams, with multistream-select on each stream.
//! 2. The Noise secure channel, or plaintext in tests.
//! 3. Multistream-select, to agree on the security protocol.
//! 4. TCP.
//!
//! The specifications are `libp2p/specs` and the consensus specs' `p2p-interface.md` files.

pub mod eth;
pub mod gossipsub;
pub mod identify;
pub mod identity;
pub mod multiaddr;
pub mod multibase;
pub mod multistream;
pub mod ping;
pub mod protobuf;
mod rng;
pub mod secure;
pub mod swarm;
pub mod varint;
pub mod yamux;

#[cfg(test)]
mod testing;

pub use identity::{KeyType, Keypair, PeerId, PeerIdError, PublicKey};
pub use multiaddr::{Multiaddr, MultiaddrError, Protocol};
