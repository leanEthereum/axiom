//! QUIC version 1, the primary libp2p transport of the consensus p2p specification.
//!
//! # Overview
//!
//! Every part is a pure state machine: datagrams and time go in, datagrams and events come out.
//! The swarm drives it over a UDP socket.
//!
//! - RFC 9000: packets, frames, streams, flow control, connection ids.
//! - RFC 9001: TLS 1.3 inside CRYPTO frames, and packet protection.
//! - RFC 9002: loss detection and congestion control.
//!
//! libp2p runs mutually authenticated TLS with the ALPN "libp2p" over it.
//! Each bidirectional stream then negotiates its protocol with multistream-select.
//! See `libp2p/specs/quic/README.md`.

mod cid;
mod config;
mod connection;
mod crypto;
mod endpoint;
mod entropy;
mod error;
mod event;
mod frame;
mod packet;
mod range_set;
mod reader;
mod recovery;
mod space;
mod stream;
#[cfg(test)]
mod testing;
mod transport_parameters;
mod varint;

pub use cid::ConnectionId;
pub use config::QuicConfig;
pub use connection::{Connection, Transmit};
pub use endpoint::{ConnectionHandle, DatagramEvent, Endpoint};
pub use entropy::Entropy;
pub use error::{ConnectionError, DecodeError, QuicError, TransportError, TransportErrorCode};
pub use event::Event;
pub use stream::{Side, StreamId, StreamLimits};
pub use varint::VarInt;

/// The QUIC version this stack speaks: version 1, RFC 9000.
pub const VERSION: u32 = 0x0000_0001;
