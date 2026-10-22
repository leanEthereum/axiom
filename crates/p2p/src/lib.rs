//! The libp2p protocol stack, and the Ethereum consensus domains built on it.
//!
//! # Overview
//!
//! Every protocol is a pure state machine first: bytes and time go in, bytes and events come out.
//! Thin tokio adapters then drive those machines over real sockets.
//!
//! ```text
//! node ── commands ──▶ ┌──────────────────────────────────────────┐ ── events ──▶ node
//!                      │ swarm (tokio)                            │
//!                      │   gossipsub router    req/resp codec     │
//!                      │   identify, ping                         │
//!                      ├──────────────────────────────────────────┤
//!                      │ yamux streams, multistream per stream    │
//!                      │ Noise secure channel (plaintext: tests)  │
//!                      │ multistream-select                       │
//!                      │ TCP                                      │
//!                      └──────────────────────────────────────────┘
//! ```
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
