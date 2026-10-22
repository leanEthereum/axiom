//! Peer discovery for the consensus client: node records and the discv5 protocol.
//!
//! # Overview
//!
//! A beacon node finds peers by walking a Kademlia table over UDP.
//! The layers, bottom up:
//!
//! ```text
//! enr       signed node records, EIP-778, with the consensus entries
//! packet    discv5 v5.1 packets: masked headers, sealed messages
//! message   PING, PONG, FINDNODE, NODES, TALKREQ, TALKRESP
//! session   handshake key agreement, identity proofs, the session cache
//! table     256 k-buckets with liveness checks and subnet caps
//! service   the protocol as a pure state machine: lookups, requests, timers
//! driver    a tokio UDP socket and clock around the service
//! ```
//!
//! The specifications are EIP-778 and the devp2p discv5 documents, protocol version v5.1.
//! The consensus entries follow the p2p interface of the consensus specs, up to Fulu.
//!
//! # Examples
//!
//! ```
//! use std::{net::Ipv4Addr, time::Duration};
//!
//! use axiom_crypto::secp256k1::SecretKey;
//! use axiom_discv5::{
//!     Enr,
//!     service::{Config, EnrFilter, Event, Output, Service},
//! };
//!
//! let key = SecretKey::from_bytes(&[1; 32]).unwrap();
//! let enr = Enr::builder()
//!     .ip4(Ipv4Addr::LOCALHOST)
//!     .udp4(9000)
//!     .build(&key)
//!     .unwrap();
//! let mut service = Service::new(key, enr.clone(), Config::default(), [7; 32]).unwrap();
//!
//! // An empty table: the lookup ends at once with no peers.
//! service.lookup(Duration::ZERO, enr.node_id(), EnrFilter::Any, 16);
//! let Some(Output::Event(Event::LookupFinished { peers, .. })) = service.poll_output() else {
//!     panic!("expected the lookup result");
//! };
//! assert!(peers.is_empty());
//! ```

mod base64;
mod distance;
pub mod driver;
pub mod enr;
pub mod message;
mod node_id;
pub mod packet;
mod rng;
pub mod service;
pub mod session;
pub mod table;

pub use base64::{Base64Error, Base64Url};
pub use distance::{Distance, DistanceError, LogDistance};
pub use enr::{Enr, EnrBuilder, EnrError};
pub use node_id::NodeId;
pub use rng::Csprng;
