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

mod decoder;
mod encoder;

pub use decoder::FrameDecoder;
pub use encoder::FrameEncoder;

use crate::{
    Crc32c, SnappyError,
    raw::{self, decompress_into, max_compressed_len},
};

/// The identifier chunk that opens every stream, header included.
const STREAM_IDENTIFIER: [u8; 10] = [0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];

/// Chunk type of the stream identifier.
const TYPE_STREAM_IDENTIFIER: u8 = 0xff;

/// Chunk type of Snappy-compressed data.
const TYPE_COMPRESSED: u8 = 0x00;

/// Chunk type of stored data.
const TYPE_UNCOMPRESSED: u8 = 0x01;

/// Last chunk type that decoders must reject.
const LAST_UNSKIPPABLE: u8 = 0x7f;

/// Bytes of a chunk header: one type byte and a 3-byte length.
const HEADER_LEN: usize = 4;

/// Bytes of the checksum that opens every data chunk body.
const CHECKSUM_LEN: usize = 4;

/// Most uncompressed bytes one data chunk may carry, fixed by the framing format.
pub const MAX_CHUNK_DATA_LEN: usize = 1 << 16;

/// Longest compressed chunk body accepted.
///
/// The format only bounds the uncompressed side.
/// No compressor exceeds the worst-case expansion of 65536 bytes, so longer bodies are rejected.
/// That keeps a decoder from buffering a 16 MiB body for 64 KiB of output.
const MAX_COMPRESSED_BODY_LEN: usize = CHECKSUM_LEN + max_compressed_len(MAX_CHUNK_DATA_LEN);

/// Longest uncompressed chunk body: a checksum and 65536 bytes.
const MAX_UNCOMPRESSED_BODY_LEN: usize = CHECKSUM_LEN + MAX_CHUNK_DATA_LEN;

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
    for data in input.chunks(MAX_CHUNK_DATA_LEN) {
        encode_chunk(data, &mut out);
    }
    out
}

/// Decompresses a whole framed stream, rejecting one that decodes past the given bound.
///
/// The stream must open with an identifier chunk.
/// Every checksum is verified.
pub fn decompress(input: &[u8], max_len: usize) -> Result<Vec<u8>, SnappyError> {
    // The first byte must already name the identifier chunk.
    if input.first() != Some(&TYPE_STREAM_IDENTIFIER) {
        return Err(SnappyError::MissingStreamIdentifier);
    }
    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let header = rest
            .first_chunk::<HEADER_LEN>()
            .ok_or(SnappyError::UnexpectedEnd)?;
        let (chunk_type, len) = parse_header(*header);
        check_body_len(chunk_type, len)?;
        let body = rest
            .get(HEADER_LEN..HEADER_LEN + len)
            .ok_or(SnappyError::UnexpectedEnd)?;
        let produced = out.len();
        decode_chunk(chunk_type, body, &mut out, produced, max_len)?;
        rest = &rest[HEADER_LEN + len..];
    }
    Ok(out)
}

/// Splits a chunk header into its type and body length.
///
/// ```text
/// [ type ][ len 0..7 ][ len 8..15 ][ len 16..23 ]
/// ```
const fn parse_header(header: [u8; HEADER_LEN]) -> (u8, usize) {
    let [chunk_type, b0, b1, b2] = header;
    let len = u32::from_le_bytes([b0, b1, b2, 0]) as usize;
    (chunk_type, len)
}

/// Rejects a body length its chunk type cannot have, before the body is read.
const fn check_body_len(chunk_type: u8, len: usize) -> Result<(), SnappyError> {
    let max = match chunk_type {
        TYPE_STREAM_IDENTIFIER if len != STREAM_IDENTIFIER.len() - HEADER_LEN => {
            return Err(SnappyError::InvalidStreamIdentifier);
        }
        TYPE_COMPRESSED => MAX_COMPRESSED_BODY_LEN,
        TYPE_UNCOMPRESSED => MAX_UNCOMPRESSED_BODY_LEN,
        // Fail on the header, so no reader buffers a body only to reject it.
        unskippable @ ..=LAST_UNSKIPPABLE => {
            return Err(SnappyError::UnskippableChunk(unskippable));
        }
        _ => return Ok(()),
    };
    if len > max {
        return Err(SnappyError::ChunkTooLarge { len, max });
    }
    if len < CHECKSUM_LEN {
        return Err(SnappyError::ChunkTooShort { len });
    }
    Ok(())
}

/// Decodes one chunk body, appending any data it carries.
///
/// # Arguments
///
/// - `produced`: bytes the stream produced before this chunk, for the total bound.
/// - `max_len`: largest total the caller accepts.
///
/// On error the output keeps only what earlier chunks produced.
fn decode_chunk(
    chunk_type: u8,
    body: &[u8],
    out: &mut Vec<u8>,
    produced: usize,
    max_len: usize,
) -> Result<(), SnappyError> {
    let start = out.len();
    let checksum = match chunk_type {
        TYPE_STREAM_IDENTIFIER => {
            // A repeated identifier is allowed, so concatenated streams decode as one.
            return if body == &STREAM_IDENTIFIER[HEADER_LEN..] {
                Ok(())
            } else {
                Err(SnappyError::InvalidStreamIdentifier)
            };
        }
        TYPE_COMPRESSED => {
            let (stored, block) = split_checksum(body)?;
            // Bound the block by both the chunk limit and what the total still allows.
            let len = raw::decompressed_len(block)?;
            check_data_len(len, produced, max_len)?;
            decompress_into(block, len, out)?;
            stored
        }
        TYPE_UNCOMPRESSED => {
            let (stored, data) = split_checksum(body)?;
            check_data_len(data.len(), produced, max_len)?;
            out.extend_from_slice(data);
            stored
        }
        unskippable @ ..=LAST_UNSKIPPABLE => {
            return Err(SnappyError::UnskippableChunk(unskippable));
        }
        // Padding and reserved skippable chunks carry nothing.
        _ => return Ok(()),
    };

    // The checksum covers the uncompressed bytes of this chunk.
    let computed = mask(Crc32c::checksum(&out[start..]));
    if computed != checksum {
        out.truncate(start);
        return Err(SnappyError::ChecksumMismatch {
            stored: checksum,
            computed,
        });
    }
    Ok(())
}

/// Splits a data chunk body into its stored checksum and its payload.
const fn split_checksum(body: &[u8]) -> Result<(u32, &[u8]), SnappyError> {
    match body.split_first_chunk::<CHECKSUM_LEN>() {
        Some((checksum, payload)) => Ok((u32::from_le_bytes(*checksum), payload)),
        None => Err(SnappyError::ChunkTooShort { len: body.len() }),
    }
}

/// Checks a chunk's data length against the chunk limit and the stream's total bound.
const fn check_data_len(len: usize, produced: usize, max_len: usize) -> Result<(), SnappyError> {
    if len > MAX_CHUNK_DATA_LEN {
        return Err(SnappyError::ChunkTooLarge {
            len,
            max: MAX_CHUNK_DATA_LEN,
        });
    }
    // Saturation keeps the sum honest even next to a bound of usize::MAX.
    let total = produced.saturating_add(len);
    if total > max_len {
        return Err(SnappyError::TooLarge {
            len: total,
            max: max_len,
        });
    }
    Ok(())
}

/// Appends one data chunk holding the given bytes.
///
/// The chunk is stored uncompressed when compression saves less than 12.5%.
/// Decoding stored data is a copy, so a small saving is not worth the decode time.
fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    debug_assert!(data.len() <= MAX_CHUNK_DATA_LEN);
    let start = out.len();
    let checksum = mask(Crc32c::checksum(data));

    // Header placeholder, then checksum, then the compressed block.
    out.extend_from_slice(&[TYPE_COMPRESSED, 0, 0, 0]);
    out.extend_from_slice(&checksum.to_le_bytes());
    let payload = out.len();
    raw::compress_into(data, out);

    if out.len() - payload >= data.len() - data.len() / 8 {
        out.truncate(payload);
        out.extend_from_slice(data);
        out[start] = TYPE_UNCOMPRESSED;
    }

    // Body length: at most 4 + 76490 bytes, well inside the 3-byte field.
    let len = (out.len() - start - HEADER_LEN).to_le_bytes();
    out[start + 1..start + HEADER_LEN].copy_from_slice(&len[..3]);
}

#[cfg(test)]
mod tests {
    use super::*;

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
        while let Some(header) = rest.first_chunk::<HEADER_LEN>() {
            let (chunk_type, len) = parse_header(*header);
            types.push(chunk_type);
            rest = &rest[HEADER_LEN + len..];
        }
        assert_eq!(
            types,
            [TYPE_STREAM_IDENTIFIER, TYPE_COMPRESSED, TYPE_UNCOMPRESSED]
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
        let mut body = vec![0, 0, 0, 0];
        raw::write_preamble(65_537, &mut body);
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
}
