//! The framing format: checksummed chunks of at most 64 KiB, for streams.
//!
//! # Overview
//!
//! A stream is a run of chunks, each with a 4-byte header.
//! Consensus req/resp carries every payload in this format.
//!
//! ```text
//! chunk:   [ type: 1 byte ][ body length: 3 bytes LE ][ body ]
//!
//! type 0xff         stream identifier, body "sNaPpY", first in every stream
//! type 0x00         compressed data:    [ masked CRC-32C: 4 bytes LE ][ raw snappy block ]
//! type 0x01         uncompressed data:  [ masked CRC-32C: 4 bytes LE ][ bytes ]
//! type 0x02..0x7f   reserved, unskippable: decoders must fail
//! type 0x80..0xfd   reserved, skippable: decoders must ignore
//! type 0xfe         padding: decoders must ignore
//! ```
//!
//! Each data chunk holds at most 65536 uncompressed bytes.
//! The checksum covers the uncompressed bytes.
//!
//! The format is specified in `google/snappy/framing_format.txt`.

mod chunk;
mod chunk_decoder;
mod chunk_encoder;
mod decoder;
mod encoder;

use chunk::{ChunkHeader, TYPE_STREAM_IDENTIFIER};
use chunk_decoder::ChunkDecoder;
use chunk_encoder::ChunkEncoder;
pub use decoder::FrameDecoder;
pub use encoder::FrameEncoder;

use crate::SnappyError;

/// The identifier chunk that opens every stream, header included.
const STREAM_IDENTIFIER: [u8; 10] = [0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];

/// Bytes of the checksum that opens every data chunk body.
const CHECKSUM_LEN: usize = 4;

/// Most uncompressed bytes one data chunk may carry, fixed by the framing format.
pub const MAX_CHUNK_DATA_LEN: usize = 1 << 16;

/// Masks a CRC so that checksums of data holding checksums stay well distributed.
///
/// ```text
/// masked = rotate_right(crc, 15) + 0xa282ead8   (mod 2^32)
/// ```
const fn mask(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

/// Compresses bytes into a framed stream.
///
/// An empty input gives a stream holding only the identifier.
#[must_use]
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = STREAM_IDENTIFIER.to_vec();
    let mut chunks = ChunkEncoder::new();
    for data in input.chunks(MAX_CHUNK_DATA_LEN) {
        chunks.encode(data, &mut out);
    }
    out
}

/// Decompresses a whole framed stream, rejecting one that decodes past the given bound.
///
/// The stream must open with an identifier chunk.
/// Every checksum is verified.
pub fn decompress(input: &[u8], max_len: usize) -> Result<Vec<u8>, SnappyError> {
    // The first byte must already name the identifier chunk, even in a truncated stream.
    if input.first() != Some(&TYPE_STREAM_IDENTIFIER) {
        return Err(SnappyError::MissingStreamIdentifier);
    }
    let mut chunks = ChunkDecoder::new(max_len);
    let mut out = Vec::new();
    let mut rest = input;
    while let Some((header, after)) = rest.split_first_chunk::<{ ChunkHeader::LEN }>() {
        let header = chunks.header(*header)?;
        let body = after.get(..header.len).ok_or(SnappyError::UnexpectedEnd)?;
        chunks.body(header, body, &mut out)?;
        rest = &after[header.len..];
    }
    // Fewer bytes than a header remain.
    if !rest.is_empty() {
        return Err(SnappyError::UnexpectedEnd);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use chunk::{ChunkType, TYPE_COMPRESSED, TYPE_UNCOMPRESSED};
    use proptest::prelude::*;

    use super::*;
    use crate::{Crc32c, raw, raw::tests::arb_data};

    /// A stream: identifier, then the given chunks.
    fn stream(chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = STREAM_IDENTIFIER.to_vec();
        for chunk in chunks {
            out.extend_from_slice(chunk);
        }
        out
    }

    /// An uncompressed chunk with a correct checksum.
    fn stored_chunk(data: &[u8]) -> Vec<u8> {
        let len = u32::try_from(CHECKSUM_LEN + data.len())
            .unwrap()
            .to_le_bytes();
        let mut chunk = vec![TYPE_UNCOMPRESSED, len[0], len[1], len[2]];
        chunk.extend_from_slice(&mask(Crc32c::checksum(data)).to_le_bytes());
        chunk.extend_from_slice(data);
        chunk
    }

    #[test]
    fn empty_input_is_the_identifier_alone() {
        // The ten bytes the framing format gives as the start of every stream.
        let framed = compress(b"");
        assert_eq!(
            framed,
            [0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]
        );
        assert_eq!(decompress(&framed, 0).unwrap(), b"");
    }

    #[test]
    fn mask_matches_the_reference_formula() {
        // Masking zero is the bare constant; masking rotates before it adds.
        assert_eq!(mask(0), 0xa282_ead8);
        assert_eq!(mask(1 << 15), 0xa282_ead9);
    }

    #[test]
    fn incompressible_data_is_stored_and_repetitive_data_compressed() {
        // 64 distinct bytes: compression cannot save 12.5%, so the chunk is stored.
        let distinct: Vec<u8> = (0..64).collect();
        let framed = compress(&distinct);
        assert_eq!(framed[10], TYPE_UNCOMPRESSED);
        assert_eq!(&framed[11..14], &[68, 0, 0]);

        // 1000 equal bytes: one literal, then 16 copies of 3 bytes each.
        let framed = compress(&[7; 1000]);
        assert_eq!(framed[10], TYPE_COMPRESSED);
        assert!(framed.len() < 100);
        assert_eq!(decompress(&framed, 1000).unwrap(), vec![7; 1000]);
    }

    #[test]
    fn data_splits_into_64_kib_chunks() {
        // 65537 bytes: one full chunk and one chunk of a single byte.
        let data = vec![1; MAX_CHUNK_DATA_LEN + 1];
        let framed = compress(&data);
        assert_eq!(decompress(&framed, data.len()).unwrap(), data);

        // Walk the headers: identifier, then exactly two data chunks.
        let mut types = Vec::new();
        let mut rest = &framed[..];
        while let Some(header) = rest.first_chunk::<{ ChunkHeader::LEN }>() {
            let header = ChunkHeader::parse(*header).unwrap();
            types.push(header.chunk_type);
            rest = &rest[ChunkHeader::LEN + header.len..];
        }
        assert_eq!(
            types,
            [
                ChunkType::StreamIdentifier,
                ChunkType::Compressed,
                ChunkType::Uncompressed
            ]
        );
    }

    #[test]
    fn stream_must_open_with_the_identifier() {
        // A data chunk first, and an empty input.
        assert_eq!(
            decompress(&stored_chunk(b"a"), 10),
            Err(SnappyError::MissingStreamIdentifier)
        );
        assert_eq!(
            decompress(&[], 10),
            Err(SnappyError::MissingStreamIdentifier)
        );
    }

    #[test]
    fn identifier_must_spell_snappy_with_the_right_length() {
        // Wrong letter case in the body.
        let mut framed = STREAM_IDENTIFIER;
        framed[4] = b'S';
        assert_eq!(
            decompress(&framed, 0),
            Err(SnappyError::InvalidStreamIdentifier)
        );

        // Length 5 instead of 6, caught from the header alone.
        assert_eq!(
            decompress(&[0xff, 0x05, 0x00, 0x00, b's', b'N', b'a', b'P', b'p'], 0),
            Err(SnappyError::InvalidStreamIdentifier)
        );
    }

    #[test]
    fn repeated_identifiers_padding_and_skippable_chunks_are_ignored() {
        // Concatenated streams, a padding chunk, and a reserved skippable chunk.
        //
        //     id | "ab" | id | pad(2) | 0x80(1) | "c"
        let framed = stream(&[
            &stored_chunk(b"ab"),
            &STREAM_IDENTIFIER,
            &[0xfe, 0x02, 0x00, 0x00, 0, 0],
            &[0x80, 0x01, 0x00, 0x00, 9],
            &stored_chunk(b"c"),
        ]);
        assert_eq!(decompress(&framed, 3).unwrap(), b"abc");
    }

    #[test]
    fn reserved_unskippable_chunks_fail() {
        // Both ends of the unskippable range.
        for chunk_type in [0x02, 0x7f] {
            let framed = stream(&[&[chunk_type, 0x00, 0x00, 0x00]]);
            assert_eq!(
                decompress(&framed, 10),
                Err(SnappyError::UnskippableChunk(chunk_type))
            );
        }
    }

    #[test]
    fn checksum_mismatch_reports_both_values() {
        // Flip one data bit after the checksum was computed.
        let mut chunk = stored_chunk(b"abc");
        let stored = mask(Crc32c::checksum(b"abc"));
        chunk[8] ^= 1;
        assert_eq!(
            decompress(&stream(&[&chunk]), 10),
            Err(SnappyError::ChecksumMismatch {
                stored,
                computed: mask(Crc32c::checksum(b"`bc")),
            })
        );
    }

    #[test]
    fn truncation_inside_a_header_or_a_body() {
        let framed = stream(&[&stored_chunk(b"abc")]);
        // Cut inside the second header, then inside the body.
        assert_eq!(
            decompress(&framed[..12], 10),
            Err(SnappyError::UnexpectedEnd)
        );
        assert_eq!(
            decompress(&framed[..framed.len() - 1], 10),
            Err(SnappyError::UnexpectedEnd)
        );
    }

    #[test]
    fn chunk_size_limits() {
        // A data body of 3 bytes cannot hold the 4-byte checksum.
        let framed = stream(&[&[TYPE_UNCOMPRESSED, 0x03, 0x00, 0x00, 1, 2, 3]]);
        assert_eq!(
            decompress(&framed, 10),
            Err(SnappyError::ChunkTooShort { len: 3 })
        );

        // An uncompressed body of 65541 bytes is one past its limit.
        let framed = stream(&[&[TYPE_UNCOMPRESSED, 0x05, 0x00, 0x01]]);
        assert_eq!(
            decompress(&framed, usize::MAX),
            Err(SnappyError::ChunkTooLarge {
                len: 65_541,
                max: 65_540
            })
        );

        // A compressed block declaring 65537 bytes breaks the per-chunk data limit.
        //
        //     body = checksum 00 00 00 00, then preamble 65537 = 0x81 0x80 0x04
        let body = [0, 0, 0, 0, 0x81, 0x80, 0x04];
        let len = u8::try_from(body.len()).unwrap();
        let mut chunk = vec![TYPE_COMPRESSED, len, 0, 0];
        chunk.extend_from_slice(&body);
        assert_eq!(
            decompress(&stream(&[&chunk]), usize::MAX),
            Err(SnappyError::ChunkTooLarge {
                len: 65_537,
                max: 65_536
            })
        );
    }

    #[test]
    fn total_bound_counts_every_chunk() {
        // Two chunks of 2 bytes against a bound of 3: the second one crosses it.
        let framed = stream(&[&stored_chunk(b"ab"), &stored_chunk(b"cd")]);
        assert_eq!(decompress(&framed, 4).unwrap(), b"abcd");
        assert_eq!(
            decompress(&framed, 3),
            Err(SnappyError::TooLarge { len: 4, max: 3 })
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        #[test]
        fn frame_round_trip_through_slices_and_streams(
            data in arb_data(),
            piece in 1_usize..5000,
        ) {
            // Law: both the one-shot functions and the io adapters invert each other.
            let framed = compress(&data);
            prop_assert_eq!(decompress(&framed, data.len()), Ok(data.clone()));

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
            let framed = compress(&data);
            let result = decompress(&framed, data.len() - 1);
            let is_too_large = matches!(result, Err(SnappyError::TooLarge { .. }));
            prop_assert!(is_too_large);
        }

        #[test]
        fn garbage_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            // Law: any bytes decode or fail, never panic, never exceed the bound.
            if let Ok(out) = raw::decompress(&bytes, 1 << 16) {
                prop_assert!(out.len() <= 1 << 16);
            }
            let _ = decompress(&bytes, 1 << 16);
            let _ = FrameDecoder::new(&bytes[..], 1 << 16).read_to_end(&mut Vec::new());
        }
    }
}
