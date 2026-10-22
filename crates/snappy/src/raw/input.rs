//! A bounds-checked read cursor over a compressed block.

use super::MAX_BLOCK_LEN;
use crate::SnappyError;

/// The unread rest of a compressed block.
///
/// Every read checks the end of input, so no block can make the decoder read out of bounds.
pub(super) struct Input<'a> {
    /// The whole block.
    bytes: &'a [u8],
    /// Position of the next unread byte.
    position: usize,
}

impl<'a> Input<'a> {
    /// A cursor at the start of a block.
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Reads the varint preamble, the uncompressed length.
    ///
    /// ```text
    /// 7 data bits per byte, least significant group first, high bit set on all but the last:
    ///
    ///     64       ->  0x40
    ///     2097150  ->  0xfe 0xff 0x7f
    /// ```
    pub(super) fn preamble(&mut self) -> Result<usize, SnappyError> {
        let mut value = 0_u64;
        // A 32-bit value needs at most 5 groups of 7 bits.
        let rest = &self.bytes[self.position..];
        for (i, &byte) in rest.iter().take(5).enumerate() {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                if value > MAX_BLOCK_LEN {
                    return Err(SnappyError::InvalidPreamble);
                }
                let len = usize::try_from(value).map_err(|_| SnappyError::InvalidPreamble)?;
                self.position += i + 1;
                return Ok(len);
            }
        }
        // Either the input ended mid-varint or a fifth byte still asked for more.
        Err(SnappyError::InvalidPreamble)
    }

    /// Reads one element tag, or nothing at the end of the block.
    #[inline]
    pub(super) fn tag(&mut self) -> Option<u8> {
        let tag = *self.bytes.get(self.position)?;
        self.position += 1;
        Some(tag)
    }

    /// Reads a little-endian integer of 1 to 4 bytes.
    #[inline]
    pub(super) fn le(&mut self, width: usize) -> Result<usize, SnappyError> {
        let bytes = self
            .bytes
            .get(self.position..self.position + width)
            .ok_or(SnappyError::UnexpectedEnd)?;
        self.position += width;
        Ok(bytes
            .iter()
            .rev()
            .fold(0, |value, &byte| (value << 8) | usize::from(byte)))
    }

    /// Reads the given number of bytes verbatim.
    #[inline]
    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], SnappyError> {
        let bytes = self
            .bytes
            .get(self.position..self.position.saturating_add(len))
            .ok_or(SnappyError::UnexpectedEnd)?;
        self.position += len;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_examples_from_the_format_description() {
        // The two worked examples of the format description, with the bytes they use.
        for (len, bytes) in [(64, &[0x40][..]), (2_097_150, &[0xfe, 0xff, 0x7f][..])] {
            let mut input = Input::new(bytes);
            assert_eq!(input.preamble(), Ok(len));
            assert_eq!(input.position, bytes.len());
        }
    }

    #[test]
    fn preamble_boundaries() {
        // 2^32 - 1 takes all 5 bytes, with only 4 bits used in the last.
        let mut input = Input::new(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(input.preamble(), Ok(u32::MAX as usize));
        assert_eq!(input.position, 5);

        // 2^32 overflows the 32-bit length.
        assert_eq!(
            Input::new(&[0x80, 0x80, 0x80, 0x80, 0x10]).preamble(),
            Err(SnappyError::InvalidPreamble)
        );

        // A sixth byte, an unfinished varint, and no input at all.
        assert_eq!(
            Input::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).preamble(),
            Err(SnappyError::InvalidPreamble)
        );
        assert_eq!(
            Input::new(&[0x80]).preamble(),
            Err(SnappyError::InvalidPreamble)
        );
        assert_eq!(
            Input::new(&[]).preamble(),
            Err(SnappyError::InvalidPreamble)
        );
    }

    #[test]
    fn reads_advance_and_stop_at_the_end() {
        // Bytes 01 02 03: a 2-byte integer 0x0201, then one byte left.
        let mut input = Input::new(&[0x01, 0x02, 0x03]);
        assert_eq!(input.le(2), Ok(0x0201));
        assert_eq!(input.take(2), Err(SnappyError::UnexpectedEnd));
        assert_eq!(input.tag(), Some(0x03));
        assert_eq!(input.tag(), None);
    }
}
