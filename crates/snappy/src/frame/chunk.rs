//! The chunk header and the checksum that opens every data chunk.

use super::{CHECKSUM_LEN, MAX_CHUNK_DATA_LEN, STREAM_IDENTIFIER};
use crate::{SnappyError, raw::max_compressed_len};

/// Type byte of the stream identifier.
pub(super) const TYPE_STREAM_IDENTIFIER: u8 = 0xff;

/// Type byte of Snappy-compressed data.
pub(super) const TYPE_COMPRESSED: u8 = 0x00;

/// Type byte of stored data.
pub(super) const TYPE_UNCOMPRESSED: u8 = 0x01;

/// Last type byte that decoders must reject.
const LAST_UNSKIPPABLE: u8 = 0x7f;

/// Longest compressed chunk body accepted.
///
/// The format only bounds the uncompressed side.
/// No compressor exceeds the worst-case expansion of 65536 bytes, so longer bodies are rejected.
/// That keeps a decoder from buffering a 16 MiB body for 64 KiB of output.
const MAX_COMPRESSED_BODY_LEN: usize = CHECKSUM_LEN + max_compressed_len(MAX_CHUNK_DATA_LEN);

/// Longest uncompressed chunk body: a checksum and 65536 bytes.
const MAX_UNCOMPRESSED_BODY_LEN: usize = CHECKSUM_LEN + MAX_CHUNK_DATA_LEN;

/// What a chunk carries, for every type a decoder accepts.
///
/// Reserved unskippable types never get this far: their header is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChunkType {
    /// The identifier that opens every stream.
    StreamIdentifier,
    /// A checksum, then one raw block.
    Compressed,
    /// A checksum, then the data verbatim.
    Uncompressed,
    /// Padding or a reserved skippable type, which decoders ignore.
    Skippable,
}

/// A validated chunk header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ChunkHeader {
    /// What the body holds.
    pub(super) chunk_type: ChunkType,
    /// Length of the body, within the limit of its type.
    pub(super) len: usize,
}

impl ChunkHeader {
    /// Bytes of a chunk header: one type byte and a 3-byte length.
    pub(super) const LEN: usize = 4;

    /// Parses a header, rejecting a body length its type cannot have before the body is read.
    ///
    /// ```text
    /// [ type ][ len 0..7 ][ len 8..15 ][ len 16..23 ]
    /// ```
    pub(super) const fn parse(header: [u8; Self::LEN]) -> Result<Self, SnappyError> {
        let [type_byte, b0, b1, b2] = header;
        let len = u32::from_le_bytes([b0, b1, b2, 0]) as usize;
        let (chunk_type, max) = match type_byte {
            TYPE_STREAM_IDENTIFIER => {
                if len != STREAM_IDENTIFIER.len() - Self::LEN {
                    return Err(SnappyError::InvalidStreamIdentifier);
                }
                return Ok(Self {
                    chunk_type: ChunkType::StreamIdentifier,
                    len,
                });
            }
            TYPE_COMPRESSED => (ChunkType::Compressed, MAX_COMPRESSED_BODY_LEN),
            TYPE_UNCOMPRESSED => (ChunkType::Uncompressed, MAX_UNCOMPRESSED_BODY_LEN),
            // Fail on the header, so no reader buffers a body only to reject it.
            unskippable @ ..=LAST_UNSKIPPABLE => {
                return Err(SnappyError::UnskippableChunk(unskippable));
            }
            _ => {
                return Ok(Self {
                    chunk_type: ChunkType::Skippable,
                    len,
                });
            }
        };
        if len > max {
            return Err(SnappyError::ChunkTooLarge { len, max });
        }
        if len < CHECKSUM_LEN {
            return Err(SnappyError::ChunkTooShort { len });
        }
        Ok(Self { chunk_type, len })
    }
}

/// The body of a data chunk, split into its stored checksum and its payload.
pub(super) struct DataChunk<'a> {
    /// Masked CRC-32C of the uncompressed bytes, as stored.
    pub(super) checksum: u32,
    /// A raw block or the data verbatim, by chunk type.
    pub(super) payload: &'a [u8],
}

impl<'a> DataChunk<'a> {
    /// Splits a data chunk body.
    pub(super) const fn split(body: &'a [u8]) -> Result<Self, SnappyError> {
        match body.split_first_chunk::<CHECKSUM_LEN>() {
            Some((checksum, payload)) => Ok(Self {
                checksum: u32::from_le_bytes(*checksum),
                payload,
            }),
            None => Err(SnappyError::ChunkTooShort { len: body.len() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_length_is_three_bytes_little_endian() {
        // Type 0x01, length 0x010203 = 66051: past the 65540 an uncompressed body allows.
        assert_eq!(
            ChunkHeader::parse([TYPE_UNCOMPRESSED, 0x03, 0x02, 0x01]),
            Err(SnappyError::ChunkTooLarge {
                len: 66_051,
                max: 65_540
            })
        );

        // Padding of 0x0200 = 512 bytes is skippable whatever its length.
        assert_eq!(
            ChunkHeader::parse([0xfe, 0x00, 0x02, 0x00]),
            Ok(ChunkHeader {
                chunk_type: ChunkType::Skippable,
                len: 512
            })
        );
    }
}
