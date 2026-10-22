//! QUIC variable-length integers, per RFC 9000, section 16.
//!
//! The two high bits of the first byte give the length: 1, 2, 4 or 8 bytes.
//! The remaining bits hold the value, big-endian.
//!
//! ```text
//! prefix  length  usable bits  largest value
//! 00      1       6            63
//! 01      2       14           16383
//! 10      4       30           1073741823
//! 11      8       62           4611686018427387903
//! ```
//!
//! Unlike the libp2p varint, QUIC does not demand the shortest encoding on input.

use super::DecodeError;

/// An integer below 2^62, the range a QUIC varint carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarInt(u64);

impl VarInt {
    /// The largest value: 2^62 - 1.
    pub const MAX: Self = Self((1 << 62) - 1);

    /// Zero.
    pub const ZERO: Self = Self(0);

    /// Wraps a value, or nothing when it reaches 2^62.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX.0 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Wraps a 32-bit value, which always fits.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value as u64)
    }

    /// Wraps a value, saturating at the largest one.
    #[must_use]
    pub const fn saturating(value: u64) -> Self {
        if value <= Self::MAX.0 {
            Self(value)
        } else {
            Self::MAX
        }
    }

    /// The value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Bytes of the shortest encoding.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self.0 {
            0..64 => 1,
            64..16_384 => 2,
            16_384..1_073_741_824 => 4,
            _ => 8,
        }
    }

    /// Appends the shortest encoding.
    pub fn encode(self, out: &mut Vec<u8>) {
        // Invariant: each arm's value fits the width it casts to, by the ranges above.
        match self.encoded_len() {
            1 => out.push(self.0 as u8),
            2 => out.extend_from_slice(&(0x4000 | self.0 as u16).to_be_bytes()),
            4 => out.extend_from_slice(&(0x8000_0000 | self.0 as u32).to_be_bytes()),
            _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | self.0).to_be_bytes()),
        }
    }

    /// Appends a two-byte encoding, used where a length is patched in after the fact.
    ///
    /// The value must be below 16384.
    pub fn encode_two_bytes(self, out: &mut [u8; 2]) {
        debug_assert!(self.0 < 16_384, "two-byte varint holds 14 bits");
        *out = (0x4000 | (self.0 as u16 & 0x3fff)).to_be_bytes();
    }

    /// Decodes one varint from the front of the input, advancing it.
    ///
    /// # Errors
    ///
    /// Fails when the input ends inside the encoding.
    pub fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let Some(&first) = input.first() else {
            return Err(DecodeError::Truncated {
                needed: 1,
                available: 0,
            });
        };
        let len = 1 << (first >> 6);
        if input.len() < len {
            return Err(DecodeError::Truncated {
                needed: len,
                available: input.len(),
            });
        }
        let (bytes, rest) = input.split_at(len);
        let mut value = u64::from(first & 0x3f);
        for byte in &bytes[1..] {
            value = (value << 8) | u64::from(*byte);
        }
        *input = rest;
        Ok(Self(value))
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::quic::testing::hex;

    #[test]
    fn rfc_9000_appendix_a1_examples() {
        // The four examples of RFC 9000, appendix A.1, one per length, plus a padded 37.
        let cases = [
            ("c2197c5eff14e88c", 151_288_809_941_952_652),
            ("9d7f3e7d", 494_878_333),
            ("7bbd", 15_293),
            ("25", 37),
            ("4025", 37),
        ];
        for (encoded, value) in cases {
            let bytes = hex(encoded);
            let mut input = bytes.as_slice();
            assert_eq!(VarInt::decode(&mut input), Ok(VarInt(value)));
            assert!(input.is_empty());
        }

        // Encoding is shortest-form, so 37 comes back as the single byte only.
        let mut out = Vec::new();
        VarInt(37).encode(&mut out);
        assert_eq!(out, hex("25"));
        out.clear();
        VarInt(151_288_809_941_952_652).encode(&mut out);
        assert_eq!(out, hex("c2197c5eff14e88c"));
    }

    #[test]
    fn length_boundaries() {
        // 63, 16383 and 2^30 - 1 are the last values of each width.
        let cases = [
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            ((1 << 30) - 1, 4),
            (1 << 30, 8),
            ((1 << 62) - 1, 8),
        ];
        for (value, len) in cases {
            assert_eq!(VarInt(value).encoded_len(), len);
        }
        assert_eq!(VarInt::new(1 << 62), None);
        assert_eq!(VarInt::saturating(u64::MAX), VarInt::MAX);
    }

    #[test]
    fn truncated_input() {
        // 0x80 announces four bytes, but only two are present.
        let mut input: &[u8] = &[0x80, 0x01];
        assert_eq!(
            VarInt::decode(&mut input),
            Err(DecodeError::Truncated {
                needed: 4,
                available: 2
            })
        );
        let mut empty: &[u8] = &[];
        assert_eq!(
            VarInt::decode(&mut empty),
            Err(DecodeError::Truncated {
                needed: 1,
                available: 0
            })
        );
    }

    #[test]
    fn two_byte_form() {
        // 1182, the Initial length of RFC 9001 appendix A.2, is 0x449e.
        let mut out = [0; 2];
        VarInt(1182).encode_two_bytes(&mut out);
        assert_eq!(out, [0x44, 0x9e]);
    }

    proptest! {
        #[test]
        fn round_trip(value in 0..=VarInt::MAX.get()) {
            let mut out = Vec::new();
            VarInt(value).encode(&mut out);
            prop_assert_eq!(out.len(), VarInt(value).encoded_len());
            let mut input = out.as_slice();
            prop_assert_eq!(VarInt::decode(&mut input), Ok(VarInt(value)));
            prop_assert!(input.is_empty());
        }
    }
}
