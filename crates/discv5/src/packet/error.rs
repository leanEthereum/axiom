//! Reasons a datagram is not a discv5 packet for this node.

use thiserror::Error;

use crate::enr::EnrError;

/// A datagram that fails to unmask or parse as a discv5 v5.1 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PacketError {
    /// The datagram is shorter than the 63-byte minimum.
    #[error("packet of {len} bytes is below 63")]
    TooSmall {
        /// Bytes in the datagram.
        len: usize,
    },

    /// The datagram exceeds the 1280-byte maximum.
    #[error("packet of {len} bytes exceeds 1280")]
    TooLarge {
        /// Bytes in the datagram.
        len: usize,
    },

    /// The unmasked header does not start with "discv5".
    ///
    /// Either another protocol sent it, or it was masked for another node.
    #[error("header does not unmask to discv5")]
    ProtocolId,

    /// The header names a version other than 1.
    #[error("protocol version {0} is not 1")]
    Version(u16),

    /// The flag names no known packet kind.
    #[error("unknown packet flag {0}")]
    Flag(u8),

    /// The authdata size does not fit the flag or the datagram.
    #[error("authdata size {size} is invalid for flag {flag}")]
    AuthDataSize {
        /// The packet kind.
        flag: u8,
        /// The declared size.
        size: u16,
    },

    /// A WHOAREYOU packet carries a message.
    #[error("WHOAREYOU packet carries a message")]
    UnexpectedMessage,

    /// A message packet's message is shorter than an authentication tag.
    #[error("message is shorter than its tag")]
    MessageTooShort,

    /// A handshake names a signature size other than 64.
    #[error("signature size {0} is not 64")]
    SignatureSize(u8),

    /// A handshake names an ephemeral key size other than 33.
    #[error("ephemeral key size {0} is not 33")]
    EphemeralKeySize(u8),

    /// A handshake's ephemeral key is not a curve point.
    #[error("ephemeral key is not on the curve")]
    EphemeralKey,

    /// A handshake carries an invalid node record.
    #[error("handshake record: {0}")]
    Record(#[source] EnrError),
}
