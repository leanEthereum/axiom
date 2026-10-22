//! Reasons a decrypted plaintext is not a protocol message.

use axiom_rlp::RlpError;
use thiserror::Error;

/// A plaintext that does not decode as a known discv5 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MessageError {
    /// The plaintext is empty.
    #[error("empty message")]
    Empty,

    /// The type byte names no supported message.
    #[error("unknown message type 0x{0:02x}")]
    UnknownType(u8),

    /// The body is not canonical RLP of the message shape.
    #[error("message body: {0}")]
    Rlp(#[from] RlpError),

    /// A request id exceeds 8 bytes.
    #[error("request id of {0} bytes exceeds 8")]
    RequestIdTooLong(usize),

    /// A requested distance exceeds 256.
    #[error("distance {0} exceeds 256")]
    Distance(u64),

    /// A recipient address is neither 4 nor 16 bytes.
    #[error("address of {0} bytes is neither IPv4 nor IPv6")]
    IpLength(usize),
}
