//! The 256-bit unsigned integer.

use std::fmt;

use crate::{DecodeError, Root, Ssz};

/// A 256-bit unsigned integer, stored as its little-endian encoding.
///
/// Consensus code mostly carries these values, such as an execution base fee.
/// The only arithmetic it needs is counting node identifiers upward, so that is all there is.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct U256(pub [u8; 32]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);

    /// The value of a 64-bit integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    /// The largest value, 2^256 - 1.
    pub const MAX: Self = Self([0xff; 32]);

    /// The next value, wrapping from the largest back to zero.
    #[must_use]
    pub fn wrapping_increment(mut self) -> Self {
        for byte in &mut self.0 {
            let (sum, carry) = byte.overflowing_add(1);
            *byte = sum;
            if !carry {
                break;
            }
        }
        self
    }

    /// The value written in decimal, or nothing when it is not a decimal below 2^256.
    #[must_use]
    pub fn from_decimal(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        let mut value = [0_u8; 32];
        for digit in text.bytes() {
            let digit = u16::from(digit.checked_sub(b'0').filter(|digit| *digit < 10)?);
            // value = value * 10 + digit, carried byte by byte from the low end.
            let mut carry = digit;
            for byte in &mut value {
                let product = u16::from(*byte) * 10 + carry;
                *byte = product as u8;
                carry = product >> 8;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(Self(value))
    }

    /// The little-endian bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl fmt::Debug for U256 {
    /// Renders big-endian hex, the order a human reads a number in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Ssz for U256 {
    const FIXED_SIZE: Option<usize> = Some(32);
    const PACKED_SIZE: Option<usize> = Some(32);

    fn encoded_len(&self) -> usize {
        32
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 32]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        Root(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_parses_little_endian() {
        // 65536 = 0x01_0000, so byte 2 holds the one.
        let mut expected = [0; 32];
        expected[2] = 1;

        assert_eq!(U256::from_decimal("65536"), Some(U256(expected)));
        assert_eq!(U256::from_decimal("12a"), None);
        assert_eq!(U256::from_decimal(""), None);
    }

    #[test]
    fn decimal_rejects_values_past_256_bits() {
        // 2^256 - 1 fits, 2^256 does not.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";

        assert_eq!(U256::from_decimal(max), Some(U256::MAX));
        assert_eq!(U256::from_decimal(over), None);
    }

    #[test]
    fn increment_carries_and_wraps() {
        let mut expected = [0; 32];
        expected[1] = 1;

        assert_eq!(U256::from_u64(255).wrapping_increment(), U256(expected));
        assert_eq!(U256::MAX.wrapping_increment(), U256::ZERO);
    }

    #[test]
    fn small_value_sits_in_the_low_bytes() {
        // 258 = 0x0102, so the encoding starts 0x02 0x01 and the rest is zero.
        let mut expected = [0; 32];
        expected[0] = 0x02;
        expected[1] = 0x01;

        assert_eq!(U256::from(258).encode(), expected);
    }
}
