//! The block decompressor, hardened for untrusted input.

use super::read_preamble;
use crate::SnappyError;

/// Appends the decompressed block to a buffer, rejecting any that declares more than the bound.
///
/// Copies reach back only into this block's own output, never into earlier bytes of the buffer.
/// On error the buffer is left as it was.
///
/// # Invariants
///
/// - Allocation happens once, for the declared length, after checking it against the bound.
/// - Every element is checked against both the input end and the declared length.
pub fn decompress_into(input: &[u8], max_len: usize, out: &mut Vec<u8>) -> Result<(), SnappyError> {
    let start = out.len();
    decode_block(input, max_len, out).inspect_err(|_| out.truncate(start))
}

/// Decodes one block onto the end of a buffer, which keeps a partial block on error.
fn decode_block(input: &[u8], max_len: usize, out: &mut Vec<u8>) -> Result<(), SnappyError> {
    let (declared, header) = read_preamble(input)?;
    if declared > max_len {
        return Err(SnappyError::TooLarge {
            len: declared,
            max: max_len,
        });
    }
    out.reserve_exact(declared);

    // Output positions are relative to this block's start.
    let base = out.len();
    let end = base + declared;
    let mut ip = header;

    while let Some(&tag) = input.get(ip) {
        ip += 1;
        let (len, offset) = match tag & 0b11 {
            0b00 => {
                // Literal: length - 1 in the tag, or in 1-4 little-endian bytes after it.
                //
                //     tag >> 2 in 0..59   ->  length = (tag >> 2) + 1
                //     tag >> 2 in 60..63  ->  (tag >> 2) - 59 extra length bytes
                let mut len = usize::from(tag >> 2);
                if len >= 60 {
                    let extra = len - 59;
                    len = read_le(input, ip, extra)?;
                    ip += extra;
                }
                // The stored value is len - 1, up to 2^32 - 1.
                // On a 32-bit target the sum can overflow, and no input is that long anyway.
                let len = len.checked_add(1).ok_or(SnappyError::UnexpectedEnd)?;
                if len > end - out.len() {
                    return Err(SnappyError::ExceedsDeclaredLength { declared });
                }
                let literal = input
                    .get(ip..ip.saturating_add(len))
                    .ok_or(SnappyError::UnexpectedEnd)?;
                out.extend_from_slice(literal);
                ip += len;
                continue;
            }
            0b01 => {
                // 1-byte offset: 3 high offset bits and length 4..11 share the tag.
                //
                //     tag:  [ offset 10..8 | length - 4 | 01 ]
                let low = read_le(input, ip, 1)?;
                ip += 1;
                (
                    4 + usize::from((tag >> 2) & 0b111),
                    (usize::from(tag >> 5) << 8) | low,
                )
            }
            0b10 => {
                let offset = read_le(input, ip, 2)?;
                ip += 2;
                (usize::from(tag >> 2) + 1, offset)
            }
            _ => {
                let offset = read_le(input, ip, 4)?;
                ip += 4;
                (usize::from(tag >> 2) + 1, offset)
            }
        };
        copy_back(out, base, end, offset, len, declared)?;
    }

    // Every byte declared must have been produced.
    let produced = out.len() - base;
    if produced != declared {
        return Err(SnappyError::ShortOfDeclaredLength { declared, produced });
    }
    Ok(())
}

/// Repeats bytes already produced, as one copy element says.
///
/// When the offset is shorter than the length, the source overlaps the destination.
/// The copy then repeats a pattern of the offset's length, run-length style.
///
/// ```text
/// out = "xab", copy offset 2, length 4:
///
///     x a b | a b a b
///           ^ each byte equals the one 2 back
/// ```
fn copy_back(
    out: &mut Vec<u8>,
    base: usize,
    end: usize,
    offset: usize,
    len: usize,
    declared: usize,
) -> Result<(), SnappyError> {
    let position = out.len() - base;
    if offset == 0 || offset > position {
        return Err(SnappyError::InvalidOffset { offset, position });
    }
    if out.len() + len > end {
        return Err(SnappyError::ExceedsDeclaredLength { declared });
    }

    let start = out.len() - offset;
    if offset >= len {
        // No overlap: one bulk copy.
        out.extend_from_within(start..start + len);
        return Ok(());
    }

    // Overlap: the source window doubles each round.
    //
    //     offset 2, length 7, pattern "ab":
    //     round 1: copy 2  ->  ab|ab
    //     round 2: copy 4  ->  ab|ab ab ab... capped at the 5 bytes left
    //
    // The window from start always holds whole periods, so copying from start stays exact.
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(out.len() - start);
        out.extend_from_within(start..start + chunk);
        remaining -= chunk;
    }
    Ok(())
}

/// Reads a little-endian integer of 1 to 4 bytes.
fn read_le(input: &[u8], at: usize, width: usize) -> Result<usize, SnappyError> {
    let bytes = input
        .get(at..at + width)
        .ok_or(SnappyError::UnexpectedEnd)?;
    Ok(bytes
        .iter()
        .rev()
        .fold(0, |value, &byte| (value << 8) | usize::from(byte)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::decompress;

    #[test]
    fn worked_example_of_the_format_description() {
        // "xababab": literal "xab", then copy offset 2 length 4.
        //
        //     07          preamble: 7 bytes
        //     08 'x' 'a' 'b'   literal, tag (3 - 1) << 2
        //     01 02       copy, 1-byte offset: len 4, offset 2
        let block = [0x07, 0x08, b'x', b'a', b'b', 0x01, 0x02];
        assert_eq!(decompress(&block, 7).unwrap(), b"xababab");
    }

    #[test]
    fn empty_block() {
        // Preamble zero and no elements.
        assert_eq!(decompress(&[0x00], 0).unwrap(), b"");
    }

    #[test]
    fn declared_length_above_the_bound_fails_before_allocating() {
        // Preamble 2^32 - 1 with no body, bounded at 1 MiB.
        let block = [0xff, 0xff, 0xff, 0xff, 0x0f];
        assert_eq!(
            decompress(&block, 1 << 20),
            Err(SnappyError::TooLarge {
                len: u32::MAX as usize,
                max: 1 << 20
            })
        );
    }

    #[test]
    fn copy_offsets_must_point_into_the_output() {
        // A copy as the first element has nothing to copy from.
        let block = [0x04, 0x01, 0x01];
        assert_eq!(
            decompress(&block, 4),
            Err(SnappyError::InvalidOffset {
                offset: 1,
                position: 0
            })
        );

        // Offset zero is never legal.
        let block = [0x05, 0x00, b'a', 0x01, 0x00];
        assert_eq!(
            decompress(&block, 5),
            Err(SnappyError::InvalidOffset {
                offset: 0,
                position: 1
            })
        );
    }

    #[test]
    fn elements_must_fill_the_declared_length_exactly() {
        // Declares 2, literal writes 3.
        let block = [0x02, 0x08, b'a', b'b', b'c'];
        assert_eq!(
            decompress(&block, 10),
            Err(SnappyError::ExceedsDeclaredLength { declared: 2 })
        );

        // Declares 4, literal writes 1.
        let block = [0x04, 0x00, b'a'];
        assert_eq!(
            decompress(&block, 10),
            Err(SnappyError::ShortOfDeclaredLength {
                declared: 4,
                produced: 1
            })
        );

        // Declares 5: one literal byte plus a copy of 5 at offset 1 makes 6.
        let block = [0x05, 0x00, b'a', 0x05, 0x01];
        assert_eq!(
            decompress(&block, 10),
            Err(SnappyError::ExceedsDeclaredLength { declared: 5 })
        );
    }

    #[test]
    fn truncated_elements() {
        // Literal promising 3 bytes, 2 present.
        assert_eq!(
            decompress(&[0x03, 0x08, b'a', b'b'], 3),
            Err(SnappyError::UnexpectedEnd)
        );
        // Literal length byte missing.
        assert_eq!(
            decompress(&[0x40, 0xf0], 64),
            Err(SnappyError::UnexpectedEnd)
        );
        // Copy offsets cut short, for each width.
        assert_eq!(
            decompress(&[0x05, 0x00, b'a', 0x01], 5),
            Err(SnappyError::UnexpectedEnd)
        );
        assert_eq!(
            decompress(&[0x05, 0x00, b'a', 0x02, 0x01], 5),
            Err(SnappyError::UnexpectedEnd)
        );
        assert_eq!(
            decompress(&[0x05, 0x00, b'a', 0x03, 0x01, 0x00, 0x00], 5),
            Err(SnappyError::UnexpectedEnd)
        );
    }

    #[test]
    fn long_literal_with_four_length_bytes() {
        // Tag 63 << 2 = 0xfc: 4 bytes of len - 1 follow, here 69999.
        let len = 70_000_usize;
        let mut block = vec![0xf0, 0xa2, 0x04];
        block.push(0xfc);
        block.extend_from_slice(&u32::try_from(len - 1).unwrap().to_le_bytes());
        block.extend(std::iter::repeat_n(9, len));
        assert_eq!(decompress(&block, len).unwrap(), vec![9; len]);
    }

    #[test]
    fn overlapping_copy_repeats_the_pattern() {
        // Pattern "abc", then a 2-byte-offset copy of 64 at offset 3.
        let block = [67, 0x08, b'a', b'b', b'c', 0xfe, 0x03, 0x00];
        let out = decompress(&block, 67).unwrap();
        let expected: Vec<u8> = b"abc".iter().copied().cycle().take(67).collect();
        assert_eq!(out, expected);
    }
}
