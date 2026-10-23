//! The libp2p TLS profile for QUIC: certificates that bind a host key, over the shared TLS 1.3 handshake.
//!
//! # Overview
//!
//! QUIC runs the TLS 1.3 handshake of RFC 8446 inside its CRYPTO frames, per RFC 9001.
//! The handshake itself lives in the TLS crate; this module fixes the libp2p profile on top of it.
//!
//! - TLS 1.3 only, with X25519 and the suites AES-128-GCM and ChaCha20-Poly1305, both on SHA-256.
//! - ECDSA P-256 with SHA-256 as the only signature scheme, offered and accepted both ways.
//! - The ALPN protocol "libp2p", and QUIC transport parameters, both mandatory.
//! - Mutual authentication: the server always requests the client certificate.
//! - No pre-shared keys, resumption, 0-RTT, KeyUpdate, or HelloRetryRequest.
//!
//! Each side proves its libp2p identity through the certificate it presents.
//! See the libp2p TLS and QUIC specs.

mod certificate;
mod identity;
mod peer;
mod session;

pub use axiom_tls::{
    Alert, CipherSuite, EcdsaSigValue, Level, ProtocolError, Secrets, TlsOutput, TrafficSecret,
};
pub use certificate::CertificateError;
pub use identity::TlsIdentity;
pub use peer::VerifiedPeer;
pub use session::TlsSession;

/// The ALPN protocol identifier libp2p negotiates over QUIC.
pub const ALPN: &[u8] = b"libp2p";

/// A failure of a libp2p TLS handshake: a protocol violation, or a refused libp2p certificate.
pub type TlsError = axiom_tls::TlsError<CertificateError>;
