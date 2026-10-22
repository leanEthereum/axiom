//! The data chunk writer shared by the slice and writer forms.

use super::{
    MAX_CHUNK_DATA_LEN,
    chunk::{ChunkHeader, TYPE_COMPRESSED, TYPE_UNCOMPRESSED},
    mask,
};
use crate::{Crc32c, raw::Encoder};

/// Encodes data chunks, reusing one block compressor for all of them.
#[derive(Clone, Debug, Default)]
pub(super) struct ChunkEncoder {
    /// Compressor of each chunk's block, whose table outlives the chunk.
    block: Encoder,
}

impl ChunkEncoder {
    /// An encoder that has not allocated anything yet.
    pub(super) const fn new() -> Self {
        Self {
            block: Encoder::new(),
        }
    }

    /// Appends one data chunk holding the given bytes.
    ///
    /// The chunk is stored uncompressed when compression saves less than 12.5%.
    /// Decoding stored data is a copy, so a small saving is not worth the decode time.
    pub(super) fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        debug_assert!(data.len() <= MAX_CHUNK_DATA_LEN);
        let start = out.len();
        let checksum = mask(Crc32c::checksum(data));

        // Header placeholder, then checksum, then the compressed block.
        out.extend_from_slice(&[TYPE_COMPRESSED, 0, 0, 0]);
        out.extend_from_slice(&checksum.to_le_bytes());
        let payload = out.len();
        self.block.compress_into(data, out);

        if out.len() - payload >= data.len() - data.len() / 8 {
            out.truncate(payload);
            out.extend_from_slice(data);
            out[start] = TYPE_UNCOMPRESSED;
        }

        // Body length: at most 4 + 76490 bytes, well inside the 3-byte field.
        let len = (out.len() - start - ChunkHeader::LEN).to_le_bytes();
        out[start + 1..start + ChunkHeader::LEN].copy_from_slice(&len[..3]);
    }
}
