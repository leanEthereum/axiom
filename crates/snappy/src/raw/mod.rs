//! The raw block format: one length preamble, then literals and back-references.
//!
//! # Overview
//!
//! A block is the uncompressed length as a varint, then a run of elements.
//! Each element either copies bytes from the input or repeats bytes already produced.
//!
//! ```text
//! [ varint: uncompressed length ][ element ][ element ] ...
//!
//! element tag, low 2 bits:
//!   00  literal                 length - 1 in the upper 6 bits, or in 1-4 extra bytes
//!   01  copy, 1-byte offset     length 4..11, offset 0..2047
//!   10  copy, 2-byte offset     length 1..64, offset 0..65535
//!   11  copy, 4-byte offset     length 1..64, offset 0..2^32 - 1
//! ```
//!
//! The format is specified in `google/snappy/format_description.txt`.
//! Consensus gossip carries every message in this format.

mod compress;
mod decompress;

pub use compress::compress_into;
pub use decompress::decompress_into;

use crate::SnappyError;

/// Longest input a block can describe, since the preamble holds a 32-bit length.
const MAX_BLOCK_LEN: u64 = u32::MAX as u64;

/// Worst-case length of the compressed form of an input of the given length.
///
/// Incompressible input grows by its literal tags, at most one byte per 6 input bytes.
/// The preamble and a final short literal fit in the extra 32 bytes.
#[must_use]
pub const fn max_compressed_len(len: usize) -> usize {
    32 + len + len / 6
}

/// Compresses bytes into one block.
///
/// # Panics
///
/// Panics when the input exceeds 2^32 - 1 bytes, the most a block can describe.
#[must_use]
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    compress_into(input, &mut out);
    out
}

/// The uncompressed length a block declares, read from its preamble alone.
///
/// No element is checked, so a valid preamble does not make the block valid.
pub fn decompressed_len(input: &[u8]) -> Result<usize, SnappyError> {
    read_preamble(input).map(|(len, _)| len)
}

/// Decompresses one block, rejecting any that declares more than the given bound.
///
/// The bound is checked before allocating, so hostile input cannot reserve memory past it.
/// Every element is bounds-checked, so no input can panic or read out of bounds.
pub fn decompress(input: &[u8], max_len: usize) -> Result<Vec<u8>, SnappyError> {
    let mut out = Vec::new();
    decompress_into(input, max_len, &mut out)?;
    Ok(out)
}

/// Reads the varint preamble.
///
/// Returns the declared length and the number of preamble bytes.
///
/// ```text
/// 7 data bits per byte, least significant group first, high bit set on all but the last:
///
///     64       ->  0x40
///     2097150  ->  0xfe 0xff 0x7f
/// ```
pub(crate) fn read_preamble(input: &[u8]) -> Result<(usize, usize), SnappyError> {
    let mut value = 0_u64;
    // A 32-bit value needs at most 5 groups of 7 bits.
    for (i, &byte) in input.iter().take(5).enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if value > MAX_BLOCK_LEN {
                return Err(SnappyError::InvalidPreamble);
            }
            let len = usize::try_from(value).map_err(|_| SnappyError::InvalidPreamble)?;
            return Ok((len, i + 1));
        }
    }
    // Either the input ended mid-varint or a fifth byte still asked for more.
    Err(SnappyError::InvalidPreamble)
}

/// Appends the varint preamble for a length.
pub(crate) fn write_preamble(len: u32, out: &mut Vec<u8>) {
    let mut value = len;
    while value >= 0x80 {
        // Low 7 bits, with the high bit flagging that more groups follow.
        out.push(value.to_le_bytes()[0] | 0x80);
        value >>= 7;
    }
    // Last group: below 0x80, so its high bit is clear.
    out.push(value.to_le_bytes()[0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_examples_from_the_format_description() {
        // The two worked examples of the format description, both ways.
        for (len, bytes) in [(64_u32, &[0x40][..]), (2_097_150, &[0xfe, 0xff, 0x7f][..])] {
            let mut out = Vec::new();
            write_preamble(len, &mut out);
            assert_eq!(out, bytes);
            assert_eq!(read_preamble(bytes), Ok((len as usize, bytes.len())));
        }
    }

    #[test]
    fn preamble_boundaries() {
        // 2^32 - 1 takes all 5 bytes, with only 4 bits used in the last.
        let max = [0xff, 0xff, 0xff, 0xff, 0x0f];
        assert_eq!(read_preamble(&max), Ok((u32::MAX as usize, 5)));

        // 2^32 overflows the 32-bit length.
        assert_eq!(
            read_preamble(&[0x80, 0x80, 0x80, 0x80, 0x10]),
            Err(SnappyError::InvalidPreamble)
        );

        // A sixth byte, an unfinished varint, and no input at all.
        assert_eq!(
            read_preamble(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            Err(SnappyError::InvalidPreamble)
        );
        assert_eq!(read_preamble(&[0x80]), Err(SnappyError::InvalidPreamble));
        assert_eq!(read_preamble(&[]), Err(SnappyError::InvalidPreamble));
    }
}
