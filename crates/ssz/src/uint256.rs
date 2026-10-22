//! The 256-bit unsigned integer.

use std::{cmp::Ordering, fmt};

use crate::{DecodeError, Root, Ssz};

/// A 256-bit unsigned integer, stored as its little-endian encoding.
///
/// Consensus code mostly carries these values, such as an execution base fee.
/// The only arithmetic it needs is counting node identifiers upward, so that is all there is.
/// Values compare as numbers, which the merge's total difficulty threshold needs.
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

    /// The value of a 128-bit integer.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        let low = value.to_le_bytes();
        let mut bytes = [0; 32];
        let mut index = 0;
        while index < 16 {
            bytes[index] = low[index];
            index += 1;
        }
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

impl Ord for U256 {
    /// Compares as numbers: the most significant byte, stored last, decides first.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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

impl fmt::Display for U256 {
    /// Renders decimal, the form the spec's configuration files write it in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = self.0;
        let mut digits = Vec::new();
        // Divide by 10 from the high byte down; each remainder is the next digit up.
        // Bound: remainder * 256 + byte <= 9 * 256 + 255 = 2559 fits in a u16.
        while value.iter().any(|byte| *byte != 0) {
            let mut remainder = 0_u16;
            for byte in value.iter_mut().rev() {
                let current = (remainder << 8) | u16::from(*byte);
                *byte = (current / 10) as u8;
                remainder = current % 10;
            }
            digits.push(char::from(b'0' + remainder as u8));
        }
        if digits.is_empty() {
            return f.write_str("0");
        }
        digits
            .iter()
            .rev()
            .try_for_each(|digit| write!(f, "{digit}"))
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
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn display_is_decimal() {
        // Zero, the mainnet terminal total difficulty, and the largest value.
        let ttd = "58750000000000000000000";
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::ZERO.to_string(), "0");
        assert_eq!(U256::from_decimal(ttd).unwrap().to_string(), ttd);
        assert_eq!(U256::MAX.to_string(), max);
    }

    proptest! {
        #[test]
        fn display_matches_native_integers(value in any::<u128>()) {
            prop_assert_eq!(U256::from_u128(value).to_string(), value.to_string());
        }
    }

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
    fn a_128_bit_value_fills_the_low_half() {
        // 2^64 sets the lowest bit of byte 8.
        let mut expected = [0; 32];
        expected[8] = 1;
        assert_eq!(U256::from_u128(1 << 64), U256(expected));
    }

    #[test]
    fn values_compare_as_numbers() {
        // 256 = 0x0100 has a zero low byte, yet exceeds 255 = 0xff.
        assert!(U256::from(256) > U256::from(255));
        assert!(U256::from(7) < U256::MAX);
        assert_eq!(U256::from(9).cmp(&U256::from(9)), Ordering::Equal);
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
