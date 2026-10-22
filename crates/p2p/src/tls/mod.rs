//! TLS 1.3 for QUIC, with libp2p peer authentication.
//!
//! # Overview
//!
//! QUIC runs the TLS 1.3 handshake of RFC 8446 inside its CRYPTO frames, per RFC 9001.
//! TLS supplies the keys; QUIC protects packets with them.
//!
//! The profile here is the one libp2p over QUIC needs, and nothing more.
//!
//! - TLS 1.3 only, with X25519 and the suites AES-128-GCM and ChaCha20-Poly1305, both on SHA-256.
//! - ECDSA P-256 with SHA-256 as the only signature scheme, offered and accepted both ways.
//! - The ALPN protocol "libp2p", and QUIC transport parameters, both mandatory.
//! - Mutual authentication: the server always requests the client certificate.
//! - No pre-shared keys, resumption, 0-RTT, KeyUpdate, or HelloRetryRequest.
//!
//! Each side proves its libp2p identity through the certificate it presents.
//! See the libp2p TLS and QUIC specs.

mod buffer;
mod certificate;
mod codec;
mod der;
mod ecdsa;
mod error;
mod extension;
mod identity;
mod key_schedule;
mod message;
mod peer;
#[cfg(test)]
mod rfc8448;
mod secret;
mod session;
mod suite;

pub use certificate::CertificateError;
pub use der::DerError;
pub use ecdsa::EcdsaSigValue;
pub use error::TlsError;
pub use identity::TlsIdentity;
pub use peer::VerifiedPeer;
pub use secret::{Secrets, TrafficSecret};
pub use session::TlsSession;
pub use suite::{CipherSuite, Level};

/// The ALPN protocol identifier libp2p negotiates over QUIC.
pub const ALPN: &[u8] = b"libp2p";

/// What the handshake asks the transport to do next, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsOutput {
    /// Send handshake bytes at a level, in CRYPTO frames.
    Handshake {
        /// The level the bytes travel at.
        level: Level,
        /// The handshake messages.
        bytes: Vec<u8>,
    },
    /// Install the keys of a level; later output and input at that level use them.
    Keys {
        /// The level the secrets key: handshake or application.
        level: Level,
        /// The secrets.
        secrets: Secrets,
    },
}
