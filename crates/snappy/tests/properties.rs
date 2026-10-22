//! Round-trip, bound, and robustness laws of both formats.

use std::io::{Read, Write};

use axiom_snappy::{
    SnappyError,
    frame::{self, FrameDecoder, FrameEncoder},
    raw,
};
use proptest::prelude::*;

/// Inputs with the structure compressors meet: runs, repeats, and noise.
fn arb_data() -> impl Strategy<Value = Vec<u8>> {
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
        let block = raw::compress(&data);
        prop_assert!(block.len() <= raw::max_compressed_len(data.len()));
        prop_assert_eq!(raw::decompressed_len(&block), Ok(data.len()));
        prop_assert_eq!(raw::decompress(&block, data.len()), Ok(data));
    }

    #[test]
    fn raw_bound_is_enforced(data in arb_data().prop_filter("non-empty", |d| !d.is_empty())) {
        // A bound one byte short of the declared length fails before decoding.
        let block = raw::compress(&data);
        let max = data.len() - 1;
        prop_assert_eq!(
            raw::decompress(&block, max),
            Err(SnappyError::TooLarge { len: data.len(), max })
        );
    }

    #[test]
    fn frame_round_trip_through_slices_and_streams(
        data in arb_data(),
        piece in 1_usize..5000,
    ) {
        // Law: both the one-shot functions and the io adapters invert each other.
        let framed = frame::compress(&data);
        prop_assert_eq!(frame::decompress(&framed, data.len()), Ok(data.clone()));

        let mut encoder = FrameEncoder::new(Vec::new());
        for chunk in data.chunks(piece) {
            encoder.write_all(chunk).unwrap();
            // Flushing mid-stream emits short chunks, which must decode the same.
            encoder.flush().unwrap();
        }
        let streamed = encoder.finish().unwrap();

        let mut decoded = Vec::new();
        FrameDecoder::new(&streamed[..], data.len())
            .read_to_end(&mut decoded)
            .unwrap();
        prop_assert_eq!(decoded, data);
    }

    #[test]
    fn frame_bound_is_enforced(data in arb_data().prop_filter("non-empty", |d| !d.is_empty())) {
        // The total bound fails at the chunk that crosses it.
        let framed = frame::compress(&data);
        let result = frame::decompress(&framed, data.len() - 1);
        let is_too_large = matches!(result, Err(SnappyError::TooLarge { .. }));
        prop_assert!(is_too_large);
    }

    #[test]
    fn garbage_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        // Law: any bytes decode or fail, never panic, never exceed the bound.
        if let Ok(out) = raw::decompress(&bytes, 1 << 16) {
            prop_assert!(out.len() <= 1 << 16);
        }
        let _ = frame::decompress(&bytes, 1 << 16);
        let _ = FrameDecoder::new(&bytes[..], 1 << 16).read_to_end(&mut Vec::new());
    }

    #[test]
    fn corrupted_blocks_never_panic(
        data in arb_data(),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
    ) {
        // Mutate a valid block in a few places and truncate it: the decoder must stay sound.
        let mut block = raw::compress(&data);
        for (at, byte) in flips {
            let i = at.index(block.len());
            block[i] ^= byte;
        }
        block.truncate(cut.index(block.len() + 1));
        if let Ok(out) = raw::decompress(&block, 1 << 16) {
            // A success must match the length the block declares.
            prop_assert_eq!(raw::decompressed_len(&block), Ok(out.len()));
        }

        // The same corruption inside a framed stream: a checksum or decode error, no panic.
        let mut framed = frame::compress(&data);
        let i = cut.index(framed.len());
        framed[i] ^= 0x55;
        let _ = frame::decompress(&framed, 1 << 16);
    }
}
