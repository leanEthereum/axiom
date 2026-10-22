//! Unsigned LEB128 varints, the length prefix of nearly every libp2p frame.
//!
//! # Overview
//!
//! A varint stores seven bits per byte, least significant group first.
//! The high bit of each byte says whether another byte follows.
//!
//! ```text
//! 300 = 0b1_0010_1100
//!
//!   byte 0:  1 0101100    continuation set, low seven bits 0x2c
//!   byte 1:  0 0000010    continuation clear, next seven bits 0x02
//!
//! wire: [0xac, 0x02]
//! ```
//!
//! Protobuf accepts up to ten bytes, enough for any 64-bit value.
//! The multiformats unsigned-varint spec caps encodings at nine bytes and requires minimality.
//! A decoder names its dialect, so the stricter rule applies only where the caller asks for it.

use thiserror::Error;

/// Longest varint any 64-bit value needs: ceil(64 / 7) bytes.
pub const MAX_LEN: usize = 10;

/// Longest varint the multiformats unsigned-varint spec allows.
///
/// Nine bytes hold 63 bits, which the spec deems enough for any length.
pub const MAX_MULTIFORMAT_LEN: usize = 9;

/// A byte string that does not start with a well-formed varint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VarintError {
    /// The encoding runs past the longest length allowed.
    #[error("varint runs past the {max}-byte limit of its dialect")]
    TooLong {
        /// Longest encoding the dialect accepts, in bytes.
        max: usize,
    },

    /// The tenth byte carries bits beyond the 64th.
    #[error("tenth varint byte {byte:#04x} overflows 64 bits")]
    Overflow {
        /// The offending tenth byte.
        byte: u8,
    },

    /// The encoding ends in a zero byte that a shorter encoding would drop.
    #[error("varint of {len} bytes ends in a redundant zero group")]
    NotMinimal {
        /// Length of the encoding, in bytes.
        len: usize,
    },

    /// The input ends before the last byte of the encoding.
    #[error("varint truncated after {len} bytes")]
    Truncated {
        /// Bytes available, all with the continuation bit set.
        len: usize,
    },
}

/// A varint dialect, which fixes the rules a decoder enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Varint {
    /// Protobuf: up to ten bytes, redundant zero groups allowed.
    Protobuf,
    /// The multiformats unsigned-varint: up to nine bytes, minimally encoded.
    Multiformat,
}

impl Varint {
    /// Longest encoding this dialect accepts.
    #[must_use]
    pub const fn max_len(self) -> usize {
        match self {
            Self::Protobuf => MAX_LEN,
            Self::Multiformat => MAX_MULTIFORMAT_LEN,
        }
    }

    /// Whether this dialect rejects a redundant trailing zero group.
    const fn requires_minimal(self) -> bool {
        matches!(self, Self::Multiformat)
    }

    /// Appends the encoding of a value: the shortest one, which every dialect reads.
    pub fn write(self, mut value: u64, out: &mut Vec<u8>) {
        // Emit seven bits at a time, setting the high bit while more remain.
        while value >= 0x80 {
            // Low seven bits of the value, plus the continuation flag.
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        // The last group fits in seven bits, so its high bit stays clear.
        out.push(value as u8);
    }

    /// Number of bytes the encoding of a value takes.
    #[must_use]
    pub const fn encoded_len(self, value: u64) -> usize {
        // Bits needed, rounded up to whole seven-bit groups, and at least one group for zero.
        let bits = 64 - (value | 1).leading_zeros() as usize;
        bits.div_ceil(7)
    }

    /// Reads one varint off the front of the input, advancing past it.
    ///
    /// # Errors
    ///
    /// Fails with a truncation error when the input ends before the last byte.
    /// A stream reader takes that as a request for more input.
    /// On any error, the input is left untouched.
    pub fn read(self, input: &mut &[u8]) -> Result<u64, VarintError> {
        let max_len = self.max_len();
        let mut value = 0u64;
        for (index, &byte) in input.iter().enumerate() {
            // Invariant: index < max_len <= 10, so the shift stays below 70 and never panics.
            if index == max_len {
                return Err(VarintError::TooLong { max: max_len });
            }
            let group = u64::from(byte & 0x7f);
            // Byte 9 starts at bit 63: only its lowest bit fits in a u64.
            //
            //     bits 0..63 from bytes 0..8, bit 63 from byte 9
            //
            // So any group above 1 in byte 9 would be lost.
            if index == 9 && group > 1 {
                return Err(VarintError::Overflow { byte });
            }
            value |= group << (7 * index);
            // A clear high bit ends the varint.
            if byte & 0x80 == 0 {
                // A trailing zero group after the first byte is redundant.
                //
                //     [0x80, 0x00] decodes to 0, but [0x00] already does
                if self.requires_minimal() && byte == 0 && index > 0 {
                    return Err(VarintError::NotMinimal { len: index + 1 });
                }
                *input = &input[index + 1..];
                return Ok(value);
            }
        }
        // Every byte so far had its continuation bit set.
        // A full-length run is already malformed; a shorter one may still complete.
        if input.len() >= max_len {
            Err(VarintError::TooLong { max: max_len })
        } else {
            Err(VarintError::Truncated { len: input.len() })
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn known_encodings() {
        // Vectors from the multiformats unsigned-varint README.
        let cases: [(u64, &[u8]); 7] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (255, &[0xff, 0x01]),
            (300, &[0xac, 0x02]),
            (16384, &[0x80, 0x80, 0x01]),
        ];
        for (value, bytes) in cases {
            // Encoding gives exactly the listed bytes.
            let mut out = Vec::new();
            Varint::Multiformat.write(value, &mut out);
            assert_eq!(out, bytes);
            assert_eq!(Varint::Multiformat.encoded_len(value), bytes.len());
            // Both dialects decode them, consuming exactly those bytes.
            for dialect in [Varint::Protobuf, Varint::Multiformat] {
                let mut input = bytes;
                assert_eq!(dialect.read(&mut input), Ok(value));
                assert_eq!(input, [0u8; 0]);
            }
        }
    }

    #[test]
    fn multiformat_limits() {
        // The unsigned-varint README caps encodings at 9 bytes, so 2^63 - 1 is the largest value.
        let largest = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        let mut out = Vec::new();
        Varint::Multiformat.write((1 << 63) - 1, &mut out);
        assert_eq!(out, largest);
        assert_eq!(
            Varint::Multiformat.read(&mut &largest[..]),
            Ok((1 << 63) - 1)
        );
        // 2^63 needs a tenth byte, which the multiformats dialect refuses.
        let mut out = Vec::new();
        Varint::Multiformat.write(1 << 63, &mut out);
        assert_eq!(out.len(), 10);
        assert_eq!(
            Varint::Multiformat.read(&mut &out[..]),
            Err(VarintError::TooLong { max: 9 })
        );
        // The README's non-minimal example: [0x81, 0x00] is 1 in Go, but only [0x01] is valid.
        assert_eq!(Varint::Protobuf.read(&mut &[0x81, 0x00][..]), Ok(1));
        assert_eq!(
            Varint::Multiformat.read(&mut &[0x81, 0x00][..]),
            Err(VarintError::NotMinimal { len: 2 })
        );
    }

    #[test]
    fn max_value_takes_ten_bytes() {
        // 2^64 - 1 needs 64 bits, so ceil(64 / 7) = 10 groups.
        let mut out = Vec::new();
        Varint::Protobuf.write(u64::MAX, &mut out);
        assert_eq!(
            out,
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
        assert_eq!(Varint::Protobuf.read(&mut &out[..]), Ok(u64::MAX));
        // The multiformats dialect stops at nine bytes.
        assert_eq!(
            Varint::Multiformat.read(&mut &out[..]),
            Err(VarintError::TooLong { max: 9 })
        );
    }

    #[test]
    fn rejects_malformed() {
        // Tenth byte holding 2 sets bit 64, which does not exist.
        let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(
            Varint::Protobuf.read(&mut &overflow[..]),
            Err(VarintError::Overflow { byte: 0x02 })
        );
        // Eleven continuation bytes never terminate within ten.
        assert_eq!(
            Varint::Protobuf.read(&mut &[0x80; 11][..]),
            Err(VarintError::TooLong { max: 10 })
        );
        // A redundant zero group: protobuf accepts it, multiformats does not.
        let mut input = &[0x80, 0x00][..];
        assert_eq!(Varint::Protobuf.read(&mut input), Ok(0));
        assert_eq!(input, [0u8; 0]);
        let mut input = &[0x80, 0x00][..];
        assert_eq!(
            Varint::Multiformat.read(&mut input),
            Err(VarintError::NotMinimal { len: 2 })
        );
        // A failed read leaves the input untouched.
        assert_eq!(input, [0x80, 0x00]);
        // A truncated varint asks for more input.
        assert_eq!(
            Varint::Protobuf.read(&mut &[0x80, 0x80][..]),
            Err(VarintError::Truncated { len: 2 })
        );
        assert_eq!(
            Varint::Protobuf.read(&mut &[][..]),
            Err(VarintError::Truncated { len: 0 })
        );
    }

    proptest! {
        #[test]
        fn round_trip(value: u64, tail in proptest::collection::vec(any::<u8>(), 0..4)) {
            // Encode, then append unrelated bytes the decoder must leave alone.
            let mut bytes = Vec::new();
            Varint::Protobuf.write(value, &mut bytes);
            bytes.extend_from_slice(&tail);
            let mut input = &bytes[..];
            prop_assert_eq!(Varint::Protobuf.read(&mut input), Ok(value));
            prop_assert_eq!(input, &tail[..]);
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..16)) {
            // Any outcome is fine, as long as the decoder returns.
            let _ = Varint::Protobuf.read(&mut &bytes[..]);
            let _ = Varint::Multiformat.read(&mut &bytes[..]);
        }
    }
}
