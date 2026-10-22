//! TLS 1.3 and TLS 1.2: the handshake, the record layer, X.509, and web PKI.
//!
//! # Overview
//!
//! One handshake serves two transports:
//!
//! - QUIC, which carries the handshake in CRYPTO frames and protects packets itself, per RFC 9001;
//! - TCP, where the record layer here frames and protects every byte, per RFC 8446.
//!
//! Who the peer must be is a profile's choice, made through a certificate verifier:
//!
//! - web PKI checks a path to a trusted root and the server's name, per RFC 5280 and RFC 9525;
//! - libp2p checks a self-signed certificate that binds a host key, in the networking crate.
//!
//! The suites are AES-128-GCM and ChaCha20-Poly1305 over SHA-256, with X25519 or P-256 key exchange.
//! A client also speaks TLS 1.2 with the same ciphers, for servers that stop there.
//!
//! The crate is pure: it reads no clock, socket, file, or entropy source.
//! The caller passes the time and the random values in.

mod alert;
mod buffer;
mod codec;
mod connection;
pub mod der;
mod ecdsa;
mod error;
mod extension;
mod group;
mod handshake;
mod hash;
mod key;
mod key_schedule;
mod message;
mod pem;
pub mod pki;
mod random;
mod record;
#[cfg(test)]
mod rfc8448;
mod secret;
mod signature;
mod suite;
#[cfg(test)]
mod testing;
mod tls12;
mod verifier;
pub mod x509;

pub use alert::{Alert, CertificateRejection};
pub use connection::Connection;
pub use ecdsa::EcdsaSigValue;
pub use error::{ProtocolError, TlsError};
pub use group::NamedGroup;
pub use handshake::{ClientConfig, Handshake, ServerConfig, TlsOutput, Transport};
pub use hash::HashAlgorithm;
pub use key::{CertifiedKey, KeyError, SigningKey};
pub use pem::{PemBlock, PemError};
pub use pki::CertificateError;
pub use random::Randomness;
pub use secret::{Secrets, TrafficSecret};
pub use signature::SignatureScheme;
pub use suite::{CipherSuite, Level};
pub use tls12::{Tls12Key, Tls12Secrets, Tls12Suite};
pub use verifier::Verifier;
