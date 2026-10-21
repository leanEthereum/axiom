//! The four-byte offsets that locate variable-size parts.

use crate::{BYTES_PER_LENGTH_OFFSET, DecodeError};

/// Reads and writes offsets.
///
/// An offset counts bytes from the start of the enclosing encoding, little-endian.
pub(crate) struct Offset;

impl Offset {
    /// Reads the offset at a position.
    pub(crate) fn read(bytes: &[u8], at: usize) -> Result<usize, DecodeError> {
        let end = at + BYTES_PER_LENGTH_OFFSET;
        let raw = bytes.get(at..end).ok_or(DecodeError::TooShort {
            minimum: end,
            actual: bytes.len(),
        })?;
        let mut word = [0; BYTES_PER_LENGTH_OFFSET];
        word.copy_from_slice(raw);
        Ok(u32::from_le_bytes(word) as usize)
    }

    /// Encodes an offset.
    ///
    /// # Panics
    ///
    /// Panics when the offset exceeds 4 GiB, which no consensus object approaches.
    pub(crate) fn encode(offset: usize) -> [u8; BYTES_PER_LENGTH_OFFSET] {
        u32::try_from(offset)
            .expect("an SSZ offset never exceeds 4 GiB")
            .to_le_bytes()
    }
}
