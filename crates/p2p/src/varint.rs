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
//! Decoders here enforce the stricter rule only where the caller asks for it.

use std::{error::Error, fmt};

/// Longest varint any 64-bit value needs: ceil(64 / 7) bytes.
pub const MAX_LEN: usize = 10;

/// Longest varint the multiformats unsigned-varint spec allows.
///
/// Nine bytes hold 63 bits, which the spec deems enough for any length.
pub const MAX_MULTIFORMAT_LEN: usize = 9;

/// A byte string that does not start with a well-formed varint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VarintError {
    /// The encoding runs past the longest length allowed.
    TooLong,

    /// The tenth byte carries bits beyond the 64th.
    Overflow,

    /// The encoding ends in a zero byte that a shorter encoding would drop.
    NotMinimal,
}

impl fmt::Display for VarintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("varint exceeds its maximum length"),
            Self::Overflow => f.write_str("varint overflows 64 bits"),
            Self::NotMinimal => f.write_str("varint is not minimally encoded"),
        }
    }
}

impl Error for VarintError {}

/// Appends the varint encoding of a value.
pub fn encode(mut value: u64, out: &mut Vec<u8>) {
    // Emit seven bits at a time, setting the high bit while more remain.
    while value >= 0x80 {
        // Low seven bits of the value, plus the continuation flag.
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    // The last group fits in seven bits, so its high bit stays clear.
    out.push(value as u8);
}

/// Number of bytes the varint encoding of a value takes.
#[must_use]
pub const fn encoded_len(value: u64) -> usize {
    // Bits needed, rounded up to whole seven-bit groups, and at least one group for zero.
    let bits = 64 - (value | 1).leading_zeros() as usize;
    bits.div_ceil(7)
}

/// Decodes a protobuf varint from the front of a byte string.
///
/// # Returns
///
/// - The value and the number of bytes it took.
/// - Nothing when the input ends before the last byte, so a stream reader can wait for more.
pub fn decode(input: &[u8]) -> Result<Option<(u64, usize)>, VarintError> {
    decode_bounded(input, MAX_LEN, false)
}

/// Decodes a multiformats unsigned-varint: at most nine bytes and minimally encoded.
pub fn decode_multiformat(input: &[u8]) -> Result<Option<(u64, usize)>, VarintError> {
    decode_bounded(input, MAX_MULTIFORMAT_LEN, true)
}

/// Decodes a varint of at most the given length, optionally requiring minimality.
fn decode_bounded(
    input: &[u8],
    max_len: usize,
    minimal: bool,
) -> Result<Option<(u64, usize)>, VarintError> {
    let mut value = 0u64;
    for (index, &byte) in input.iter().enumerate() {
        // Invariant: index < max_len <= 10, so the shift stays below 70 and never panics.
        if index == max_len {
            return Err(VarintError::TooLong);
        }
        let group = u64::from(byte & 0x7f);
        // Byte 9 starts at bit 63: only its lowest bit fits in a u64.
        //
        //     bits 0..63 from bytes 0..8, bit 63 from byte 9
        //     → any group above 1 in byte 9 would be lost
        if index == 9 && group > 1 {
            return Err(VarintError::Overflow);
        }
        value |= group << (7 * index);
        // A clear high bit ends the varint.
        if byte & 0x80 == 0 {
            // A trailing zero group after the first byte is redundant.
            //
            //     [0x80, 0x00] decodes to 0, but [0x00] already does
            if minimal && byte == 0 && index > 0 {
                return Err(VarintError::NotMinimal);
            }
            return Ok(Some((value, index + 1)));
        }
    }
    // Every byte so far had its continuation bit set.
    // A full-length run is already malformed; a shorter one may still complete.
    if input.len() >= max_len {
        Err(VarintError::TooLong)
    } else {
        Ok(None)
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
            encode(value, &mut out);
            assert_eq!(out, bytes);
            assert_eq!(encoded_len(value), bytes.len());
            // Decoding consumes exactly those bytes.
            assert_eq!(decode(bytes), Ok(Some((value, bytes.len()))));
        }
    }

    #[test]
    fn max_value_takes_ten_bytes() {
        // 2^64 - 1 needs 64 bits → ceil(64 / 7) = 10 groups.
        let mut out = Vec::new();
        encode(u64::MAX, &mut out);
        assert_eq!(
            out,
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
        assert_eq!(decode(&out), Ok(Some((u64::MAX, 10))));
        // The multiformats flavour stops at nine bytes.
        assert_eq!(decode_multiformat(&out), Err(VarintError::TooLong));
    }

    #[test]
    fn rejects_malformed() {
        // Tenth byte holding 2 sets bit 64, which does not exist.
        let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(decode(&overflow), Err(VarintError::Overflow));
        // Eleven continuation bytes never terminate within ten.
        assert_eq!(decode(&[0x80; 11]), Err(VarintError::TooLong));
        // A redundant zero group: protobuf accepts it, multiformats does not.
        assert_eq!(decode(&[0x80, 0x00]), Ok(Some((0, 2))));
        assert_eq!(
            decode_multiformat(&[0x80, 0x00]),
            Err(VarintError::NotMinimal)
        );
        // A truncated varint asks for more input.
        assert_eq!(decode(&[0x80, 0x80]), Ok(None));
        assert_eq!(decode(&[]), Ok(None));
    }

    proptest! {
        #[test]
        fn round_trip(value: u64, tail in proptest::collection::vec(any::<u8>(), 0..4)) {
            // Encode, then append unrelated bytes the decoder must leave alone.
            let mut bytes = Vec::new();
            encode(value, &mut bytes);
            let len = bytes.len();
            bytes.extend_from_slice(&tail);
            prop_assert_eq!(decode(&bytes), Ok(Some((value, len))));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..16)) {
            // Any outcome is fine, as long as the decoder returns.
            let _ = decode(&bytes);
            let _ = decode_multiformat(&bytes);
        }
    }
}
