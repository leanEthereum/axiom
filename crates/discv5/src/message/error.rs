//! Reasons a decrypted plaintext is not a protocol message.

use std::{error::Error, fmt};

use axiom_rlp::RlpError;

/// A plaintext that does not decode as a known discv5 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageError {
    /// The plaintext is empty.
    Empty,

    /// The type byte names no supported message.
    UnknownType(u8),

    /// The body is not canonical RLP of the message shape.
    Rlp(RlpError),

    /// A request id exceeds 8 bytes.
    RequestIdTooLong(usize),

    /// A requested distance exceeds 256.
    Distance(u64),

    /// A recipient address is neither 4 nor 16 bytes.
    IpLength(usize),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty message"),
            Self::UnknownType(kind) => write!(f, "unknown message type 0x{kind:02x}"),
            Self::Rlp(error) => write!(f, "message body: {error}"),
            Self::RequestIdTooLong(len) => write!(f, "request id of {len} bytes exceeds 8"),
            Self::Distance(distance) => write!(f, "distance {distance} exceeds 256"),
            Self::IpLength(len) => write!(f, "address of {len} bytes is neither IPv4 nor IPv6"),
        }
    }
}

impl Error for MessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rlp(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RlpError> for MessageError {
    fn from(error: RlpError) -> Self {
        Self::Rlp(error)
    }
}
