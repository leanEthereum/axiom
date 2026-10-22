//! The block decompressor, hardened for untrusted input.

use super::input::Input;
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
    BlockDecoder::new(input, max_len, out)
        .and_then(BlockDecoder::decode)
        .inspect_err(|_| out.truncate(start))
}

/// The state of one block decode: the input cursor and the output it fills.
struct BlockDecoder<'a, 'o> {
    /// The unread elements.
    input: Input<'a>,
    /// The buffer the block appends to.
    out: &'o mut Vec<u8>,
    /// Length of the buffer before this block, where copies stop reaching back.
    base: usize,
    /// Length the preamble declares.
    declared: usize,
}

impl<'a, 'o> BlockDecoder<'a, 'o> {
    /// Reads the preamble and reserves the declared length, once it passes the bound.
    fn new(input: &'a [u8], max_len: usize, out: &'o mut Vec<u8>) -> Result<Self, SnappyError> {
        let mut input = Input::new(input);
        let declared = input.preamble()?;
        if declared > max_len {
            return Err(SnappyError::TooLarge {
                len: declared,
                max: max_len,
            });
        }
        out.reserve_exact(declared);
        Ok(Self {
            input,
            base: out.len(),
            out,
            declared,
        })
    }

    /// Output position where this block ends.
    #[inline]
    const fn end(&self) -> usize {
        self.base + self.declared
    }

    /// Decodes every element, leaving a partial block on the buffer on error.
    fn decode(mut self) -> Result<(), SnappyError> {
        while let Some(tag) = self.input.tag() {
            let (len, offset) = match tag & 0b11 {
                0b00 => {
                    self.literal(tag)?;
                    continue;
                }
                0b01 => {
                    // 1-byte offset: 3 high offset bits and length 4..11 share the tag.
                    //
                    //     tag:  [ offset 10..8 | length - 4 | 01 ]
                    let low = self.input.le(1)?;
                    (
                        4 + usize::from((tag >> 2) & 0b111),
                        (usize::from(tag >> 5) << 8) | low,
                    )
                }
                0b10 => (usize::from(tag >> 2) + 1, self.input.le(2)?),
                _ => (usize::from(tag >> 2) + 1, self.input.le(4)?),
            };
            self.copy_back(offset, len)?;
        }

        // Every byte declared must have been produced.
        let produced = self.out.len() - self.base;
        if produced != self.declared {
            return Err(SnappyError::ShortOfDeclaredLength {
                declared: self.declared,
                produced,
            });
        }
        Ok(())
    }

    /// Copies a literal element's bytes to the output.
    #[inline]
    fn literal(&mut self, tag: u8) -> Result<(), SnappyError> {
        // Length - 1 in the tag, or in 1-4 little-endian bytes after it.
        //
        //     tag >> 2 in 0..59   ->  length = (tag >> 2) + 1
        //     tag >> 2 in 60..63  ->  (tag >> 2) - 59 extra length bytes
        let mut len = usize::from(tag >> 2);
        if len >= 60 {
            len = self.input.le(len - 59)?;
        }
        // The stored value is len - 1, up to 2^32 - 1.
        // On a 32-bit target the sum can overflow, and no input is that long anyway.
        let len = len.checked_add(1).ok_or(SnappyError::UnexpectedEnd)?;
        if len > self.end() - self.out.len() {
            return Err(SnappyError::ExceedsDeclaredLength {
                declared: self.declared,
            });
        }
        let literal = self.input.take(len)?;
        self.out.extend_from_slice(literal);
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
    #[inline]
    fn copy_back(&mut self, offset: usize, len: usize) -> Result<(), SnappyError> {
        let end = self.end();
        let out = &mut *self.out;
        let position = out.len() - self.base;
        if offset == 0 || offset > position {
            return Err(SnappyError::InvalidOffset { offset, position });
        }
        if out.len() + len > end {
            return Err(SnappyError::ExceedsDeclaredLength {
                declared: self.declared,
            });
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
