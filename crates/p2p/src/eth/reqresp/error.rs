//! Reasons a request or response stream is malformed.

use axiom_snappy::SnappyError;
use thiserror::Error;

use crate::varint::VarintError;

/// A violation of the ssz_snappy encoding rules.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ReqRespError {
    /// The length prefix is not a valid varint of at most 10 bytes.
    #[error("invalid length prefix: {0}")]
    Varint(#[from] VarintError),

    /// The declared SSZ length is outside the bounds of the type or the payload limit.
    #[error("declared length {len} outside {min}..={max}")]
    InvalidLength {
        /// Declared length.
        len: u64,
        /// Shortest valid length.
        min: u64,
        /// Longest valid length.
        max: u64,
    },

    /// The framed stream does not open with the snappy stream identifier.
    #[error("framed stream opens with chunk type {chunk_type:#04x}, not the stream identifier")]
    MissingStreamIdentifier {
        /// Type byte of the first chunk.
        chunk_type: u8,
    },

    /// The framed stream exceeds the worst-case compressed size of its declared length.
    #[error("compressed payload reaches {len} bytes, above the bound of {max}")]
    CompressedTooLarge {
        /// Framed bytes after the identifier, the offending chunk included.
        len: usize,
        /// Largest compressed length allowed.
        max: usize,
    },

    /// The snappy frames are malformed or decode past the declared length.
    #[error("invalid snappy frames: {0}")]
    Snappy(#[from] SnappyError),

    /// The request stream exceeds the largest framed request of its method.
    #[error("request of {len} bytes exceeds the framed bound of {max}")]
    RequestTooLarge {
        /// Bytes received.
        len: usize,
        /// Largest framed request.
        max: usize,
    },

    /// Bytes follow a complete request.
    #[error("{len} bytes follow the end of the payload")]
    TrailingBytes {
        /// Bytes received after the payload.
        len: usize,
    },

    /// The stream ended inside a request or a response chunk.
    #[error("stream ended inside a payload after {received} bytes")]
    UnexpectedEof {
        /// Bytes the stream delivered in all.
        received: usize,
    },
}
