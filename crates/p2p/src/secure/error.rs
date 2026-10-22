//! Reasons a secure channel fails.

use std::{error::Error, fmt};

use crate::{identity::PeerId, protobuf::ProtobufError};

/// A failed handshake or a corrupted protected stream.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecureError {
    /// A handshake message is not valid protobuf or has a malformed frame.
    Framing(ProtobufError),

    /// A handshake message is shorter than its pattern requires.
    MessageTooShort,

    /// The peer's identity key or identifier is malformed.
    InvalidIdentity,

    /// The claimed identifier does not match the claimed key.
    IdentifierMismatch,

    /// The proven identity is not the peer the dialer meant to reach.
    UnexpectedPeer {
        /// The peer the dialer asked for.
        expected: PeerId,
        /// The peer that answered.
        actual: PeerId,
    },

    /// The identity signature over the static key does not verify.
    InvalidSignature,

    /// A Diffie-Hellman input or output is invalid.
    InvalidKey,

    /// A ciphertext fails authentication.
    DecryptionFailed,

    /// A cipher used up its 2^64 - 1 nonces.
    NonceExhausted,

    /// The handshake received more bytes after its last message was due.
    UnexpectedData,
}

impl From<ProtobufError> for SecureError {
    fn from(error: ProtobufError) -> Self {
        Self::Framing(error)
    }
}

impl fmt::Display for SecureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(error) => write!(f, "malformed handshake message: {error}"),
            Self::MessageTooShort => f.write_str("handshake message too short"),
            Self::InvalidIdentity => f.write_str("malformed identity"),
            Self::IdentifierMismatch => f.write_str("peer id does not match public key"),
            Self::UnexpectedPeer { expected, actual } => {
                write!(f, "dialed {expected} but reached {actual}")
            }
            Self::InvalidSignature => f.write_str("identity signature does not verify"),
            Self::InvalidKey => f.write_str("invalid Diffie-Hellman key"),
            Self::DecryptionFailed => f.write_str("ciphertext fails authentication"),
            Self::NonceExhausted => f.write_str("cipher nonces exhausted"),
            Self::UnexpectedData => f.write_str("unexpected data during handshake"),
        }
    }
}

impl Error for SecureError {}
