//! The deflate symbol alphabets and the fixed Huffman code over them.
//!
//! Source: RFC 1951 sections 3.2.5 and 3.2.6.

/// The symbol that closes a block.
pub(super) const END_OF_BLOCK: u16 = 256;

/// The first symbol of the length alphabet, which follows the 256 literals and the end marker.
pub(super) const FIRST_LENGTH_SYMBOL: u16 = 257;

/// The match lengths, in 29 ranges, each a base and a count of extra bits.
///
/// Source: RFC 1951 section 3.2.5, the table of length codes 257 to 285.
///
/// The last range holds only 258, so the longest match costs no extra bits.
pub(super) const LENGTHS: Ranges<29> = Ranges {
    bases: [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ],
    extra: [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ],
};

/// The match distances, in 30 ranges, each a base and a count of extra bits.
///
/// Source: RFC 1951 section 3.2.5, the table of distance codes 0 to 29.
pub(super) const DISTANCES: Ranges<30> = Ranges {
    bases: [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ],
    extra: [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ],
};

/// Consecutive value ranges, each named by a symbol and refined by extra bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Ranges<const N: usize> {
    /// The smallest value of each range, ascending.
    bases: [u16; N],

    /// How many extra bits pick the value inside each range.
    extra: [u8; N],
}

impl<const N: usize> Ranges<N> {
    /// The range holding a value, with the value's offset into it.
    ///
    /// The value must be at least the first base.
    pub(super) fn classify(&self, value: u16) -> Classified {
        // The last base not above the value; ties go to the later range, so 258 takes its own.
        let index = self.bases.partition_point(|&base| base <= value) - 1;
        Classified {
            index,
            offset: u32::from(value - self.bases[index]),
            width: u32::from(self.extra[index]),
        }
    }
}

/// A value split into its range index and its offset inside the range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Classified {
    /// The index of the range, which is the symbol relative to its alphabet.
    pub(super) index: usize,

    /// The value minus the range's base.
    pub(super) offset: u32,

    /// The number of extra bits that carry the offset.
    pub(super) width: u32,
}

/// A Huffman code word, most significant bit first as RFC 1951 defines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Code {
    /// The code word, right-aligned.
    pub(super) bits: u32,

    /// The number of bits in the code word.
    pub(super) width: u32,
}

impl Code {
    /// The fixed code of a literal, length, or end-of-block symbol.
    ///
    /// Source: RFC 1951 section 3.2.6.
    ///
    /// ```text
    ///     symbols   0 to 143   8 bits   from 00110000
    ///     symbols 144 to 255   9 bits   from 110010000
    ///     symbols 256 to 279   7 bits   from 0000000
    ///     symbols 280 to 287   8 bits   from 11000000
    /// ```
    pub(super) const fn literal_length(symbol: u16) -> Self {
        let symbol = symbol as u32;
        match symbol {
            0..=143 => Self {
                bits: 0x30 + symbol,
                width: 8,
            },
            144..=255 => Self {
                bits: 0x190 + symbol - 144,
                width: 9,
            },
            256..=279 => Self {
                bits: symbol - 256,
                width: 7,
            },
            _ => Self {
                bits: 0xc0 + symbol - 280,
                width: 8,
            },
        }
    }

    /// The fixed code of a distance symbol: its index in five bits.
    ///
    /// Source: RFC 1951 section 3.2.6.
    pub(super) const fn distance(symbol: u16) -> Self {
        Self {
            bits: symbol as u32,
            width: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_length_has_one_range() {
        // Each length from 3 to 258 lands in a range whose extra bits can carry its offset.
        for length in 3..=258 {
            let classified = LENGTHS.classify(length);
            assert!(classified.offset < 1 << classified.width, "{length}");
        }
        // The boundaries: the first length, the last 5-bit range, and the dedicated 258.
        assert_eq!(
            LENGTHS.classify(3),
            Classified {
                index: 0,
                offset: 0,
                width: 0
            }
        );
        assert_eq!(
            LENGTHS.classify(257),
            Classified {
                index: 27,
                offset: 30,
                width: 5
            }
        );
        assert_eq!(
            LENGTHS.classify(258),
            Classified {
                index: 28,
                offset: 0,
                width: 0
            }
        );
    }

    #[test]
    fn every_distance_has_one_range() {
        // Each distance from 1 to 32768 lands in a range whose extra bits can carry its offset.
        for distance in 1..=32768 {
            let classified = DISTANCES.classify(distance);
            assert!(classified.offset < 1 << classified.width, "{distance}");
        }
        // The farthest distance is the top of the last range.
        assert_eq!(
            DISTANCES.classify(32768),
            Classified {
                index: 29,
                offset: 8191,
                width: 13
            }
        );
    }

    #[test]
    fn fixed_code_boundaries() {
        // The first and last symbol of each of the four groups.
        let expected = [
            (0, 0b0011_0000, 8),
            (143, 0b1011_1111, 8),
            (144, 0b1_1001_0000, 9),
            (255, 0b1_1111_1111, 9),
            (256, 0b000_0000, 7),
            (279, 0b001_0111, 7),
            (280, 0b1100_0000, 8),
            (287, 0b1100_0111, 8),
        ];
        for (symbol, bits, width) in expected {
            assert_eq!(
                Code::literal_length(symbol),
                Code { bits, width },
                "{symbol}"
            );
        }
    }
}
