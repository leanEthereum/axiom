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

    /// A handshake message is shorter than its pattern requires.
    #[error("handshake message too short")]
    MessageTooShort,

    /// The peer's identity key or identifier is malformed.
    #[error("malformed identity")]
    InvalidIdentity,

    /// The claimed identifier does not match the claimed key.
    #[error("peer id does not match public key")]
    IdentifierMismatch,

    /// The proven identity is not the peer the dialer meant to reach.
    #[error("dialed {expected} but reached {actual}")]
    UnexpectedPeer {
        /// The peer the dialer asked for.
        expected: PeerId,
        /// The peer that answered.
        actual: PeerId,
    },

    /// The identity signature over the static key does not verify.
    #[error("identity signature does not verify")]
    InvalidSignature,

    /// A Diffie-Hellman input or output is invalid.
    #[error("invalid Diffie-Hellman key")]
    InvalidKey,

    /// A ciphertext fails authentication.
    #[error("ciphertext fails authentication")]
    DecryptionFailed,

    /// A cipher used up its 2^64 - 1 nonces.
    #[error("cipher nonces exhausted")]
    NonceExhausted,

    /// The handshake received more bytes after its last message was due.
    #[error("unexpected data during handshake")]
    UnexpectedData,
}
