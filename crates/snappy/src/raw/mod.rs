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

mod decoder;
mod encoder;
mod input;
mod sink;
mod table;

pub use decoder::decompress_into;
pub use encoder::Encoder;
use input::Input;

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
/// Each call allocates a fresh hash table; a long-lived encoder reuses one.
///
/// # Panics
///
/// Panics when the input exceeds 2^32 - 1 bytes, the most a block can describe.
#[must_use]
pub fn compress(input: &[u8]) -> Vec<u8> {
    Encoder::new().compress(input)
}

/// The uncompressed length a block declares, read from its preamble alone.
///
/// No element is checked, so a valid preamble does not make the block valid.
pub fn decompressed_len(input: &[u8]) -> Result<usize, SnappyError> {
    Input::new(input).preamble()
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

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::frame;

    /// Inputs with the structure compressors meet: runs, repeats, and noise.
    pub(crate) fn arb_data() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // Pure noise: mostly literals.
            prop::collection::vec(any::<u8>(), 0..3000),
            // A small alphabet: short, frequent matches.
            prop::collection::vec(0_u8..4, 0..3000),
            // Repeated random pieces: long matches at varied offsets.
            (prop::collection::vec(any::<u8>(), 1..40), 1_usize..200)
                .prop_map(|(piece, times)| piece.repeat(times)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        #[test]
        fn raw_round_trip(data in arb_data()) {
            // Law: decompress(compress(x)) == x, within the worst-case size.
            let block = compress(&data);
            prop_assert!(block.len() <= max_compressed_len(data.len()));
            prop_assert_eq!(decompressed_len(&block), Ok(data.len()));
            prop_assert_eq!(decompress(&block, data.len()), Ok(data));
        }

        #[test]
        fn raw_bound_is_enforced(data in arb_data().prop_filter("non-empty", |d| !d.is_empty())) {
            // A bound one byte short of the declared length fails before decoding.
            let block = compress(&data);
            let max = data.len() - 1;
            prop_assert_eq!(
                decompress(&block, max),
                Err(SnappyError::TooLarge { len: data.len(), max })
            );
        }

        #[test]
        fn corrupted_blocks_never_panic(
            data in arb_data(),
            flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
            cut in any::<prop::sample::Index>(),
        ) {
            // Mutate a valid block in a few places and truncate it: the decoder must stay sound.
            let mut block = compress(&data);
            for (at, byte) in flips {
                let i = at.index(block.len());
                block[i] ^= byte;
            }
            block.truncate(cut.index(block.len() + 1));
            if let Ok(out) = decompress(&block, 1 << 16) {
                // A success must match the length the block declares.
                prop_assert_eq!(decompressed_len(&block), Ok(out.len()));
            }

            // The same corruption inside a framed stream: a checksum or decode error, no panic.
            let mut framed = frame::compress(&data);
            let i = cut.index(framed.len());
            framed[i] ^= 0x55;
            let _ = frame::decompress(&framed, 1 << 16);
        }
    }
}
