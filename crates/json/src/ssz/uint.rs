//! Unsigned integers of any SSZ width, between little-endian bytes and decimal text.

/// A little-endian unsigned integer of up to 32 bytes.
///
/// SSZ integers reach 256 bits, past every native type, so the arithmetic runs on bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LittleEndian(Vec<u8>);

impl LittleEndian {
    /// Reads decimal digits into a value of a given width, or nothing when they do not fit.
    ///
    /// Leading zeros are accepted, signs and other characters are not.
    pub(super) fn from_decimal(text: &str, width: usize) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        let mut value = vec![0_u8; width];
        for digit in text.bytes() {
            let digit = u16::from(digit.checked_sub(b'0').filter(|digit| *digit < 10)?);
            // value = value * 10 + digit, carried byte by byte from the low end.
            // Bound: 255 * 10 + 255 = 2805 fits in a u16.
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

    /// Wraps little-endian bytes.
    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The little-endian bytes.
    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The value in decimal, without leading zeros.
    pub(super) fn to_decimal(&self) -> String {
        let mut value = self.0.clone();
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
            digits.push(b'0' + remainder as u8);
        }
        if digits.is_empty() {
            return "0".to_owned();
        }
        digits.reverse();
        // Invariant: every pushed byte is an ASCII digit.
        String::from_utf8(digits).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn boundaries_of_each_width() {
        // 255 fits one byte, 256 does not.
        assert_eq!(
            LittleEndian::from_decimal("255", 1),
            Some(LittleEndian(vec![0xff]))
        );
        assert_eq!(LittleEndian::from_decimal("256", 1), None);

        // 2^256 - 1 is the largest 32-byte value; one more overflows.
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let above =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert_eq!(
            LittleEndian::from_decimal(max, 32),
            Some(LittleEndian(vec![0xff; 32]))
        );
        assert_eq!(LittleEndian::from_decimal(above, 32), None);

        // Zero prints as one digit, and leading zeros read as nothing.
        assert_eq!(LittleEndian(vec![0; 8]).to_decimal(), "0");
        assert_eq!(
            LittleEndian::from_decimal("007", 2),
            Some(LittleEndian(vec![7, 0]))
        );
    }

    #[test]
    fn malformed_text_is_refused() {
        // Empty text, a sign, and a hex prefix are not decimal.
        for text in ["", "-1", "+1", "0x10", "1.0"] {
            assert_eq!(LittleEndian::from_decimal(text, 8), None, "{text}");
        }
    }

    proptest! {
        #[test]
        fn decimal_matches_native_integers(value in any::<u128>()) {
            // The byte arithmetic agrees with the native 128-bit formatter and parser.
            let text = value.to_string();
            let bytes = LittleEndian::from_bytes(&value.to_le_bytes());
            prop_assert_eq!(LittleEndian::from_decimal(&text, 16), Some(bytes.clone()));
            prop_assert_eq!(bytes.to_decimal(), text);
        }
    }
}
