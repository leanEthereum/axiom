//! Reasons a request or response stream is malformed.

use std::{error::Error, fmt};

use axiom_snappy::SnappyError;

use crate::varint::VarintError;

/// A violation of the ssz_snappy encoding rules.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReqRespError {
    /// The length prefix is not a valid varint of at most 10 bytes.
    Varint(VarintError),

    /// The declared SSZ length is outside the bounds of the type or the payload limit.
    InvalidLength {
        /// Declared length.
        len: u64,
        /// Shortest valid length.
        min: u64,
        /// Longest valid length.
        max: u64,
    },

    /// The framed stream does not open with the snappy stream identifier.
    MissingStreamIdentifier,

    /// The framed stream exceeds the worst-case compressed size of its declared length.
    CompressedTooLarge {
        /// Largest compressed length allowed.
        max: usize,
    },

    /// The snappy frames are malformed or decode past the declared length.
    Snappy(SnappyError),

    /// Bytes follow a complete request.
    TrailingBytes,

    /// The stream ended inside a request or a response chunk.
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

impl fmt::Display for ReqRespError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Varint(error) => write!(f, "invalid length prefix: {error}"),
            Self::InvalidLength { len, min, max } => {
                write!(f, "declared length {len} outside {min}..={max}")
            }
            Self::MissingStreamIdentifier => f.write_str("missing snappy stream identifier"),
            Self::CompressedTooLarge { max } => {
                write!(f, "compressed payload exceeds {max} bytes")
            }
            Self::Snappy(error) => write!(f, "invalid snappy frames: {error}"),
            Self::TrailingBytes => f.write_str("bytes after the end of the payload"),
            Self::UnexpectedEof => f.write_str("stream ended inside a payload"),
        }
    }
}

impl Error for ReqRespError {}
