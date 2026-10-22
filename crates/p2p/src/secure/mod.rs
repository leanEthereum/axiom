//! The secure channel seam: authenticating the peer and protecting the bytes.
//!
//! # Overview
//!
//! After multistream-select picks a security protocol, a handshake runs on the raw stream.
//! It proves the remote identity and yields two half-duplex ciphers.
//!
//! ```text
//! raw stream ──▶ handshake (bytes in, bytes out) ──▶ secure session
//!                                                     ├ remote peer id, proven
//!                                                     ├ sealer: plaintext → wire bytes
//!                                                     └ opener: wire bytes → plaintext
//! ```
//!
//! The halves are separate, so a reader task and a writer task each own one.
//!
//! # Extension point
//!
//! A security protocol implements three small traits: an upgrade, a handshake, and the two ciphers.
//! Two protocols ship.
//!
//! - Noise XX over X25519, ChaCha20-Poly1305, and SHA-256, with secp256k1 identities.
//!   It is the default for every real connection.
//! - A plaintext exchange, for tests only: it authenticates nothing.

mod error;
pub mod noise;
pub mod plaintext;

use std::fmt;

pub use error::SecureError;

use crate::identity::{PeerId, PublicKey};

/// Which side of the handshake this node plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The dialer, which speaks first.
    Initiator,
    /// The listener.
    Responder,
}

/// A security protocol that can start handshakes.
pub trait SecurityUpgrade: Send + Sync + fmt::Debug {
    /// The multistream-select name of the protocol.
    fn protocol(&self) -> &'static str;

    /// Starts a handshake.
    ///
    /// # Arguments
    ///
    /// - `role`: the side this node plays.
    /// - `expected`: the peer the dialer meant to reach, checked once the handshake proves an identity.
    fn handshake(&self, role: Role, expected: Option<PeerId>) -> Box<dyn Handshake>;
}

/// A running handshake, driven by bytes in and bytes out.
pub trait Handshake: Send {
    /// Takes the bytes to write to the stream.
    ///
    /// Call it after every input, including the one that completes the handshake.
    fn take_output(&mut self) -> Vec<u8>;

    /// Feeds bytes read from the stream.
    ///
    /// # Returns
    ///
    /// The session once the handshake completes, or nothing while it is pending.
    fn receive(&mut self, bytes: &[u8]) -> Result<Option<SecureSession>, SecureError>;
}

/// Turns plaintext into protected wire bytes.
pub trait Seal: Send + fmt::Debug {
    /// Appends the wire form of a plaintext.
    fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), SecureError>;
}

/// Turns protected wire bytes back into plaintext.
pub trait Open: Send + fmt::Debug {
    /// Feeds wire bytes in any chunking, appending every complete plaintext.
    ///
    /// Partial frames stay buffered until the rest arrives.
    fn open(&mut self, wire: &[u8], out: &mut Vec<u8>) -> Result<(), SecureError>;
}

/// The outcome of a completed handshake.
#[derive(Debug)]
pub struct SecureSession {
    /// The identifier the handshake proved, or claimed under plaintext.
    pub remote_peer: PeerId,
    /// The remote identity key.
    pub remote_key: PublicKey,
    /// Protects outbound bytes.
    pub sealer: Box<dyn Seal>,
    /// Unprotects inbound bytes.
    pub opener: Box<dyn Open>,
    /// Plaintext that arrived together with the last handshake message.
    pub early_plaintext: Vec<u8>,
}
