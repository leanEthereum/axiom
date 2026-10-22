//! The CRC-32 checksum that closes every gzip member.

/// The reflected form of the IEEE 802.3 generator polynomial.
///
/// Source: RFC 1952 section 8, which gives the polynomial and the reflected bit order.
const POLYNOMIAL: u32 = 0xedb8_8320;

/// The remainder of every single byte, so the update consumes a byte per lookup.
const TABLE: [u32; 256] = Crc32::table();

/// A running CRC-32 over a byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Crc32 {
    /// The register, kept inverted between updates.
    register: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        // The register starts at all ones, so leading zero bytes still change it.
        Self { register: u32::MAX }
    }
}

impl Crc32 {
    /// Builds the per-byte remainder table at compile time.
    const fn table() -> [u32; 256] {
        let mut table = [0; 256];
        let mut byte = 0;
        while byte < 256 {
            // Divide one byte by the polynomial, one bit at a time, low bit first.
            let mut remainder = byte as u32;
            let mut bit = 0;
            while bit < 8 {
                remainder = if remainder & 1 == 1 {
                    (remainder >> 1) ^ POLYNOMIAL
                } else {
                    remainder >> 1
                };
                bit += 1;
            }
            table[byte] = remainder;
            byte += 1;
        }
        table
    }

    /// Folds more bytes into the checksum.
    pub(super) fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            // The low byte of the register meets the input; the table supplies its remainder.
            let index = usize::from((self.register as u8) ^ byte);
            self.register = TABLE[index] ^ (self.register >> 8);
        }
    }

    /// The checksum of every byte folded so far.
    pub(super) const fn value(self) -> u32 {
        // The final inversion undoes the all-ones start.
        !self.register
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The checksum of one buffer.
    fn checksum(bytes: &[u8]) -> u32 {
        let mut crc = Crc32::default();
        crc.update(bytes);
        crc.value()
    }

    /// The bitwise definition, one bit per step, with no table.
    fn bitwise(bytes: &[u8]) -> u32 {
        let mut register = u32::MAX;
        for &byte in bytes {
            register ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (register & 1).wrapping_neg();
                register = (register >> 1) ^ (POLYNOMIAL & mask);
            }
        }
        !register
    }

    #[test]
    fn check_value_matches_the_catalogue() {
        // The catalogue's check value: the CRC of the nine ASCII digits.
        assert_eq!(checksum(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn empty_input_checksums_to_zero() {
        // All ones inverted is zero.
        assert_eq!(checksum(b""), 0);
    }

    proptest! {
        #[test]
        fn split_updates_equal_one_update(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            cut in 0usize..512,
        ) {
            // Two updates at any cut fold the same bytes as one.
            let cut = cut.min(bytes.len());
            let mut split = Crc32::default();
            split.update(&bytes[..cut]);
            split.update(&bytes[cut..]);
            prop_assert_eq!(split.value(), checksum(&bytes));
        }

        #[test]
        fn table_matches_the_bitwise_definition(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            // The byte-at-a-time table is the bitwise division, eight steps at once.
            prop_assert_eq!(checksum(&bytes), bitwise(&bytes));
        }
    }
}
