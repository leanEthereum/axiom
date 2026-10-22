//! Reasons compressed input fails to decode.

use std::io;

use thiserror::Error;

/// Input that is not valid Snappy data, or that decodes past the caller's bound.
///
/// Decoders stop at the first broken rule, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SnappyError {
    /// The leading varint of a block is truncated, longer than 5 bytes, or above 2^32 - 1.
    #[error("invalid length preamble")]
    InvalidPreamble,

    /// The input ends inside an element, a chunk header, or a chunk body.
    ///
    /// Both counts start where the truncated part starts.
    #[error("input ends with {available} of {needed} bytes")]
    UnexpectedEnd {
        /// Bytes the part needs.
        needed: usize,
        /// Bytes the input still held.
        available: usize,
    },

    /// The output would exceed the caller's bound.
    ///
    /// The check runs before any allocation of that size.
    #[error("output of {len} bytes exceeds the limit of {max}")]
    TooLarge {
        /// Length the input declares or would produce.
        len: usize,
        /// Largest length the caller accepts.
        max: usize,
    },

    /// A copy points at offset zero or before the start of the output.
    #[error("copy offset {offset} is invalid at output position {position}")]
    InvalidOffset {
        /// Distance back the copy asked for.
        offset: usize,
        /// Bytes of output produced before the copy.
        position: usize,
    },

    /// An element writes past the length the block declares.
    #[error("elements reach {reached} bytes, past the declared length {declared}")]
    ExceedsDeclaredLength {
        /// Length the block declares.
        declared: usize,
        /// Length the output would reach with the offending element.
        reached: usize,
    },

    /// The elements end before producing the length the block declares.
    #[error("elements produce {produced} bytes, declared {declared}")]
    ShortOfDeclaredLength {
        /// Length the block declares.
        declared: usize,
        /// Length the elements produce.
        produced: usize,
    },

    /// A framed stream does not open with a stream identifier chunk.
    #[error("stream does not start with an identifier")]
    MissingStreamIdentifier,

    /// A stream identifier chunk does not hold exactly the bytes `sNaPpY`.
    #[error("invalid stream identifier chunk")]
    InvalidStreamIdentifier,

    /// A chunk uses a reserved type that decoders must not skip.
    #[error("reserved unskippable chunk type {0:#04x}")]
    UnskippableChunk(u8),

    /// A data chunk's body is too short to hold its 4-byte checksum.
    #[error("data chunk of {len} bytes cannot hold a checksum")]
    ChunkTooShort {
        /// Length of the body.
        len: usize,
    },

    /// A chunk's body is longer than its type allows.
    #[error("chunk of {len} bytes exceeds the limit of {max}")]
    ChunkTooLarge {
        /// Length of the body.
        len: usize,
        /// Longest body the type allows.
        max: usize,
    },

    /// The checksum of a data chunk does not match its uncompressed bytes.
    #[error("checksum {computed:#010x} does not match stored {stored:#010x}")]
    ChecksumMismatch {
        /// Masked checksum stored in the chunk.
        stored: u32,
        /// Masked checksum of the decoded bytes.
        computed: u32,
    },
}

impl From<SnappyError> for io::Error {
    /// Wraps a decoding error as an I/O error of the matching kind.
    ///
    /// Truncation reports an unexpected end of file, and every other error invalid data.
    fn from(err: SnappyError) -> Self {
        let kind = if matches!(err, SnappyError::UnexpectedEnd { .. }) {
            io::ErrorKind::UnexpectedEof
        } else {
            io::ErrorKind::InvalidData
        };
        Self::new(kind, err)
    }
}
