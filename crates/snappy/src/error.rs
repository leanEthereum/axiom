//! Reasons compressed input fails to decode.

use std::{error::Error, fmt};

/// Input that is not valid Snappy data, or that decodes past the caller's bound.
///
/// Decoders stop at the first broken rule, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnappyError {
    /// The leading varint of a block is truncated, longer than 5 bytes, or above 2^32 - 1.
    InvalidPreamble,

    /// The input ends inside an element, a chunk header, or a chunk body.
    UnexpectedEnd,

    /// The output would exceed the caller's bound.
    ///
    /// The check runs before any allocation of that size.
    TooLarge {
        /// Length the input declares or would produce.
        len: usize,
        /// Largest length the caller accepts.
        max: usize,
    },

    /// A copy points at offset zero or before the start of the output.
    InvalidOffset {
        /// Distance back the copy asked for.
        offset: usize,
        /// Bytes of output produced before the copy.
        position: usize,
    },

    /// An element writes past the length the block declares.
    ExceedsDeclaredLength {
        /// Length the block declares.
        declared: usize,
    },

    /// The elements end before producing the length the block declares.
    ShortOfDeclaredLength {
        /// Length the block declares.
        declared: usize,
        /// Length the elements produce.
        produced: usize,
    },

    /// A framed stream does not open with a stream identifier chunk.
    MissingStreamIdentifier,

    /// A stream identifier chunk does not hold exactly the bytes `sNaPpY`.
    InvalidStreamIdentifier,

    /// A chunk uses a reserved type that decoders must not skip.
    UnskippableChunk(u8),

    /// A data chunk's body is too short to hold its 4-byte checksum.
    ChunkTooShort {
        /// Length of the body.
        len: usize,
    },

    /// A chunk's body is longer than its type allows.
    ChunkTooLarge {
        /// Length of the body.
        len: usize,
        /// Longest body the type allows.
        max: usize,
    },

    /// The checksum of a data chunk does not match its uncompressed bytes.
    ChecksumMismatch {
        /// Masked checksum stored in the chunk.
        stored: u32,
        /// Masked checksum of the decoded bytes.
        computed: u32,
    },
}

impl fmt::Display for SnappyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPreamble => f.write_str("invalid length preamble"),
            Self::UnexpectedEnd => f.write_str("input ends unexpectedly"),
            Self::TooLarge { len, max } => {
                write!(f, "output of {len} bytes exceeds the limit of {max}")
            }
            Self::InvalidOffset { offset, position } => {
                write!(
                    f,
                    "copy offset {offset} is invalid at output position {position}"
                )
            }
            Self::ExceedsDeclaredLength { declared } => {
                write!(f, "elements write past the declared length {declared}")
            }
            Self::ShortOfDeclaredLength { declared, produced } => {
                write!(f, "elements produce {produced} bytes, declared {declared}")
            }
            Self::MissingStreamIdentifier => {
                f.write_str("stream does not start with an identifier")
            }
            Self::InvalidStreamIdentifier => f.write_str("invalid stream identifier chunk"),
            Self::UnskippableChunk(chunk_type) => {
                write!(f, "reserved unskippable chunk type {chunk_type:#04x}")
            }
            Self::ChunkTooShort { len } => {
                write!(f, "data chunk of {len} bytes cannot hold a checksum")
            }
            Self::ChunkTooLarge { len, max } => {
                write!(f, "chunk of {len} bytes exceeds the limit of {max}")
            }
            Self::ChecksumMismatch { stored, computed } => {
                write!(
                    f,
                    "checksum {computed:#010x} does not match stored {stored:#010x}"
                )
            }
        }
    }
}

impl Error for SnappyError {}
