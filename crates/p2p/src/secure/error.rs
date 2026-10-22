//! Reasons a secure channel fails.

use thiserror::Error;

use crate::{identity::PeerId, protobuf::ProtobufError};

/// A failed handshake or a corrupted protected stream.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SecureError {
    /// A handshake message is not valid protobuf or has a malformed frame.
    #[error("malformed handshake message: {0}")]
    Framing(#[from] ProtobufError),

    /// A message is shorter than the token or tag it must carry.
    #[error("message of {len} bytes is shorter than the {needed} bytes it must carry")]
    MessageTooShort {
        /// Bytes the next token or tag needs.
        needed: usize,
        /// Bytes the message holds.
        len: usize,
    },

    /// The handshake payload carries no identity key.
    #[error("handshake payload lacks the identity key")]
    InvalidIdentity,

    /// The claimed identifier does not match the claimed key.
    #[error("peer claims id {claimed} but its key derives {derived}")]
    IdentifierMismatch {
        /// The identifier the peer announced.
        claimed: PeerId,
        /// The identifier its announced key derives.
        derived: PeerId,
    },

    /// The proven identity is not the peer the dialer meant to reach.
    #[error("dialed {expected} but reached {actual}")]
    UnexpectedPeer {
        /// The peer the dialer asked for.
        expected: PeerId,
        /// The peer that answered.
        actual: PeerId,
    },

    /// The identity signature over the static key is absent or does not verify.
    #[error("identity signature of {peer} over its static key is absent or invalid")]
    InvalidSignature {
        /// The peer whose identity key the payload claims.
        peer: PeerId,
    },

    /// A Diffie-Hellman input or output is invalid.
    #[error("invalid Diffie-Hellman key")]
    InvalidKey,

    /// A ciphertext fails authentication.
    #[error("ciphertext at nonce {nonce} fails authentication")]
    DecryptionFailed {
        /// The nonce the ciphertext was opened with.
        nonce: u64,
    },

    /// A cipher used up its 2^64 - 1 nonces.
    #[error("cipher nonces exhausted")]
    NonceExhausted,

    /// The handshake received more bytes after it ended, by success or failure.
    #[error("{len} bytes arrived after the handshake ended")]
    UnexpectedData {
        /// Bytes received after the end.
        len: usize,
    },
}
