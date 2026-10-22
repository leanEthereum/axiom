//! The element writer of the block compressor.

/// A cursor writing a block into a buffer already sized for the worst case.
///
/// Every write indexes the buffer directly, with no capacity check or reallocation.
pub(super) struct Sink<'a> {
    /// The output space.
    buf: &'a mut [u8],
    /// Bytes written so far.
    len: usize,
}

impl<'a> Sink<'a> {
    /// A sink writing from the start of the given space.
    pub(super) const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Bytes written so far.
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Writes one byte.
    #[inline]
    const fn push(&mut self, byte: u8) {
        self.buf[self.len] = byte;
        self.len += 1;
    }

    /// Writes a run of bytes.
    #[inline]
    fn extend(&mut self, bytes: &[u8]) {
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// Writes the varint preamble holding the uncompressed length.
    ///
    /// ```text
    /// 7 data bits per byte, least significant group first, high bit set on all but the last:
    ///
    ///     64       ->  0x40
    ///     2097150  ->  0xfe 0xff 0x7f
    /// ```
    pub(super) const fn preamble(&mut self, len: u32) {
        let mut value = len;
        while value >= 0x80 {
            // Low 7 bits, with the high bit flagging that more groups follow.
            self.push(value.to_le_bytes()[0] | 0x80);
            value >>= 7;
        }
        // Last group: below 0x80, so its high bit is clear.
        self.push(value.to_le_bytes()[0]);
    }

    /// Writes a literal element: a tag, then the bytes verbatim.
    ///
    /// ```text
    /// length 1..60:   [ (len - 1) << 2 | 00 ][ bytes ]
    /// length > 60:    [ (59 + k) << 2 | 00 ][ len - 1 as k little-endian bytes ][ bytes ]
    /// ```
    #[expect(
        clippy::cast_possible_truncation,
        reason = "each cast follows a range check that makes it exact"
    )]
    pub(super) fn literal(&mut self, bytes: &[u8]) {
        let Some(n) = bytes.len().checked_sub(1) else {
            return;
        };
        if n < 60 {
            self.push((n as u8) << 2);
        } else {
            // Count the bytes of len - 1: 1 to 4, since fragments stay below 2^32.
            let extra = n.bit_width().div_ceil(8) as usize;
            self.push(((59 + extra) as u8) << 2);
            self.extend(&n.to_le_bytes()[..extra]);
        }
        self.extend(bytes);
    }

    /// Writes copy elements for a back-reference of any length.
    ///
    /// One element holds at most 64 bytes.
    /// Long matches split into 64-byte pieces that leave at least 4 bytes for the last one.
    /// That keeps the last piece eligible for the short 1-byte-offset form.
    pub(super) fn copy(&mut self, offset: usize, mut len: usize) {
        while len >= 68 {
            self.copy_upto_64(offset, 64);
            len -= 64;
        }
        // 65..67 bytes: 60 now leaves 5..7 for the last piece.
        if len > 64 {
            self.copy_upto_64(offset, 60);
            len -= 60;
        }
        self.copy_upto_64(offset, len);
    }

    /// Writes one copy element of 1 to 64 bytes in its shortest form.
    ///
    /// ```text
    /// 1-byte offset, len 4..11, offset < 2048:
    ///     [ offset >> 8 : 3 bits | len - 4 : 3 bits | 01 ][ offset & 0xff ]
    /// 2-byte offset, offset < 65536:
    ///     [ len - 1 : 6 bits | 10 ][ offset : u16 little-endian ]
    /// 4-byte offset:
    ///     [ len - 1 : 6 bits | 11 ][ offset : u32 little-endian ]
    /// ```
    #[expect(
        clippy::cast_possible_truncation,
        reason = "each cast follows a range check that makes it exact"
    )]
    fn copy_upto_64(&mut self, offset: usize, len: usize) {
        debug_assert!((1..=64).contains(&len) && offset > 0);
        if (4..12).contains(&len) && offset < 2048 {
            self.push(0b01 | (((len - 4) as u8) << 2) | (((offset >> 8) as u8) << 5));
            self.push(offset as u8);
        } else if offset < 1 << 16 {
            self.push(0b10 | (((len - 1) as u8) << 2));
            self.extend(&(offset as u16).to_le_bytes());
        } else {
            self.push(0b11 | (((len - 1) as u8) << 2));
            self.extend(&(offset as u32).to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::decompress;

    /// The bytes a sink writes for one call.
    fn emitted(write: impl FnOnce(&mut Sink<'_>)) -> Vec<u8> {
        let mut buf = vec![0; 300];
        let mut sink = Sink::new(&mut buf);
        write(&mut sink);
        let len = sink.len();
        buf.truncate(len);
        buf
    }

    #[test]
    fn preamble_examples_from_the_format_description() {
        // The two worked examples of the format description.
        assert_eq!(emitted(|s| s.preamble(64)), [0x40]);
        assert_eq!(emitted(|s| s.preamble(2_097_150)), [0xfe, 0xff, 0x7f]);

        // 2^32 - 1 takes all 5 bytes, with only 4 bits used in the last.
        assert_eq!(
            emitted(|s| s.preamble(u32::MAX)),
            [0xff, 0xff, 0xff, 0xff, 0x0f]
        );
    }

    #[test]
    fn literal_tags_at_each_length_boundary() {
        // 60 bytes: the largest length held in the tag itself, (60 - 1) << 2 = 0xec.
        let bytes = emitted(|s| s.literal(&[7; 60]));
        assert_eq!(bytes[0], 0xec);
        assert_eq!(bytes.len(), 1 + 60);

        // 61 bytes: tag 60 << 2 = 0xf0, then one length byte holding 60.
        let bytes = emitted(|s| s.literal(&[7; 61]));
        assert_eq!(&bytes[..2], &[0xf0, 60]);

        // 257 bytes: len - 1 = 256 needs two bytes, tag 61 << 2 = 0xf4.
        let bytes = emitted(|s| s.literal(&[1; 257]));
        assert_eq!(&bytes[..3], &[0xf4, 0x00, 0x01]);

        // An empty literal writes nothing.
        assert_eq!(emitted(|s| s.literal(&[])), Vec::<u8>::new());
    }

    #[test]
    fn copy_forms_by_length_and_offset() {
        // Short and near: 1-byte offset, len 11, offset 2047.
        //
        //     tag = (2047 >> 8) << 5 | (11 - 4) << 2 | 01 = 0xfd
        assert_eq!(emitted(|s| s.copy(2047, 11)), [0xfd, 0xff]);

        // Offset 2048 no longer fits 11 bits: 2-byte form, tag (11 - 1) << 2 | 10 = 0x2a.
        assert_eq!(emitted(|s| s.copy(2048, 11)), [0x2a, 0x00, 0x08]);

        // Length 12 no longer fits 3 bits: 2-byte form even for a small offset.
        assert_eq!(emitted(|s| s.copy(1, 12)), [0x2e, 0x01, 0x00]);

        // Offset 65536 needs the 4-byte form, tag (4 - 1) << 2 | 11 = 0x0f.
        assert_eq!(
            emitted(|s| s.copy(65_536, 4)),
            [0x0f, 0x00, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn long_copies_split_keeping_four_bytes_for_the_last_piece() {
        // 67 bytes at offset 1: 60 + 7, never 64 + 3.
        //
        //     piece 1: len 60, 2-byte form   [ 0xee, 0x01, 0x00 ]
        //     piece 2: len 7,  1-byte form   [ 0x0d, 0x01 ]
        assert_eq!(emitted(|s| s.copy(1, 67)), [0xee, 0x01, 0x00, 0x0d, 0x01]);

        // 68 bytes: 64 + 4.
        assert_eq!(emitted(|s| s.copy(1, 68)), [0xfe, 0x01, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn four_byte_offsets_decode() {
        // Build a block by hand: 70000 literal bytes, then a 4-byte-offset copy of 8.
        //
        //     output[70000..70008] = output[0..8]
        let head: Vec<u8> = (0..70_000_u32).map(|i| (i % 251) as u8).collect();
        let mut block = vec![0; 70_100];
        let mut sink = Sink::new(&mut block);
        sink.preamble(70_008);
        sink.literal(&head);
        sink.copy(70_000, 8);
        let len = sink.len();
        block.truncate(len);

        // The copy reaches back past 2^16, which only the 4-byte form can say.
        let out = decompress(&block, 70_008).unwrap();
        assert_eq!(&out[..70_000], &head[..]);
        assert_eq!(&out[70_000..], &head[..8]);
    }
}
