//! The chunk-by-chunk decoding core shared by the slice and reader forms.

use super::{
    MAX_CHUNK_DATA_LEN, STREAM_IDENTIFIER,
    chunk::{ChunkHeader, ChunkType, DataChunk, TYPE_STREAM_IDENTIFIER},
};
use crate::{Crc32c, SnappyError, raw};

/// Decodes the chunks of one stream in order, against a bound on the total output.
#[derive(Clone, Copy, Debug)]
pub(super) struct ChunkDecoder {
    /// Largest total of decompressed bytes accepted.
    max_len: usize,
    /// Decompressed bytes produced so far.
    produced: usize,
    /// Whether the stream identifier was read.
    started: bool,
}

impl ChunkDecoder {
    /// A decoder at the start of a stream, producing at most the given number of bytes.
    pub(super) const fn new(max_len: usize) -> Self {
        Self {
            max_len,
            produced: 0,
            started: false,
        }
    }

    /// Whether the stream identifier was read, so the stream may end cleanly.
    pub(super) const fn started(&self) -> bool {
        self.started
    }

    /// Parses the next chunk header, which must be the identifier at the start of a stream.
    pub(super) const fn header(
        &mut self,
        header: [u8; ChunkHeader::LEN],
    ) -> Result<ChunkHeader, SnappyError> {
        if !self.started && header[0] != TYPE_STREAM_IDENTIFIER {
            return Err(SnappyError::MissingStreamIdentifier);
        }
        self.started = true;
        ChunkHeader::parse(header)
    }

    /// Decodes one chunk body, appending any data it carries.
    ///
    /// On error the output keeps only what earlier chunks produced.
    pub(super) fn body(
        &mut self,
        header: ChunkHeader,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SnappyError> {
        let start = out.len();
        let checksum = match header.chunk_type {
            ChunkType::StreamIdentifier => {
                // A repeated identifier is allowed, so concatenated streams decode as one.
                return if body == &STREAM_IDENTIFIER[ChunkHeader::LEN..] {
                    Ok(())
                } else {
                    Err(SnappyError::InvalidStreamIdentifier)
                };
            }
            ChunkType::Compressed => {
                let chunk = DataChunk::split(body)?;
                // Bound the block by both the chunk limit and what the total still allows.
                let len = raw::decompressed_len(chunk.payload)?;
                self.admit(len)?;
                raw::decompress_into(chunk.payload, len, out)?;
                chunk.checksum
            }
            ChunkType::Uncompressed => {
                let chunk = DataChunk::split(body)?;
                self.admit(chunk.payload.len())?;
                out.extend_from_slice(chunk.payload);
                chunk.checksum
            }
            // Padding and reserved skippable chunks carry nothing.
            ChunkType::Skippable => return Ok(()),
        };

        // The checksum covers the uncompressed bytes of this chunk.
        let computed = Crc32c::masked(&out[start..]);
        if computed != checksum {
            out.truncate(start);
            return Err(SnappyError::ChecksumMismatch {
                stored: checksum,
                computed,
            });
        }
        self.produced += out.len() - start;
        Ok(())
    }

    /// Checks a chunk's data length against the chunk limit and the stream's total bound.
    const fn admit(&self, len: usize) -> Result<(), SnappyError> {
        if len > MAX_CHUNK_DATA_LEN {
            return Err(SnappyError::ChunkTooLarge {
                len,
                max: MAX_CHUNK_DATA_LEN,
            });
        }
        // Saturation keeps the sum honest even next to a bound of usize::MAX.
        let total = self.produced.saturating_add(len);
        if total > self.max_len {
            return Err(SnappyError::TooLarge {
                len: total,
                max: self.max_len,
            });
        }
        Ok(())
    }
}
