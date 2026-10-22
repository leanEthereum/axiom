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
    Varint(VarintError),

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
    #[error("missing snappy stream identifier")]
    MissingStreamIdentifier,

    /// The framed stream exceeds the worst-case compressed size of its declared length.
    #[error("compressed payload exceeds {max} bytes")]
    CompressedTooLarge {
        /// Largest compressed length allowed.
        max: usize,
    },

    /// The snappy frames are malformed or decode past the declared length.
    #[error("invalid snappy frames: {0}")]
    Snappy(SnappyError),

    /// Bytes follow a complete request.
    #[error("bytes after the end of the payload")]
    TrailingBytes,

    /// The stream ended inside a request or a response chunk.
    #[error("stream ended inside a payload")]
    UnexpectedEof,
}

impl From<VarintError> for ReqRespError {
    fn from(error: VarintError) -> Self {
        Self::Varint(error)
    }
}

impl From<SnappyError> for ReqRespError {
    fn from(error: SnappyError) -> Self {
        Self::Snappy(error)
    }
}
