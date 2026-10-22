//! Reasons a datagram is not a discv5 packet for this node.

use std::{error::Error, fmt};

use crate::enr::EnrError;

/// A datagram that fails to unmask or parse as a discv5 v5.1 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketError {
    /// The datagram is shorter than the 63-byte minimum.
    TooSmall {
        /// Bytes in the datagram.
        len: usize,
    },

    /// The datagram exceeds the 1280-byte maximum.
    TooLarge {
        /// Bytes in the datagram.
        len: usize,
    },

    /// The unmasked header does not start with "discv5".
    ///
    /// Either another protocol sent it, or it was masked for another node.
    ProtocolId,

    /// The header names a version other than 1.
    Version(u16),

    /// The flag names no known packet kind.
    Flag(u8),

    /// The authdata size does not fit the flag or the datagram.
    AuthDataSize {
        /// The packet kind.
        flag: u8,
        /// The declared size.
        size: u16,
    },

    /// A WHOAREYOU packet carries a message.
    UnexpectedMessage,

    /// A message packet's message is shorter than an authentication tag.
    MessageTooShort,

    /// A handshake names a signature size other than 64.
    SignatureSize(u8),

    /// A handshake names an ephemeral key size other than 33.
    EphemeralKeySize(u8),

    /// A handshake's ephemeral key is not a curve point.
    EphemeralKey,

    /// A handshake carries an invalid node record.
    Record(EnrError),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall { len } => write!(f, "packet of {len} bytes is below 63"),
            Self::TooLarge { len } => write!(f, "packet of {len} bytes exceeds 1280"),
            Self::ProtocolId => f.write_str("header does not unmask to discv5"),
            Self::Version(version) => write!(f, "protocol version {version} is not 1"),
            Self::Flag(flag) => write!(f, "unknown packet flag {flag}"),
            Self::AuthDataSize { flag, size } => {
                write!(f, "authdata size {size} is invalid for flag {flag}")
            }
            Self::UnexpectedMessage => f.write_str("WHOAREYOU packet carries a message"),
            Self::MessageTooShort => f.write_str("message is shorter than its tag"),
            Self::SignatureSize(size) => write!(f, "signature size {size} is not 64"),
            Self::EphemeralKeySize(size) => write!(f, "ephemeral key size {size} is not 33"),
            Self::EphemeralKey => f.write_str("ephemeral key is not on the curve"),
            Self::Record(error) => write!(f, "handshake record: {error}"),
        }
    }
}

impl Error for PacketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            _ => None,
        }
    }
}
