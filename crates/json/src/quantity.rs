//! QUANTITY: an integer as 0x-prefixed hex with no leading zeros.
//!
//! The encoding comes from the Ethereum JSON-RPC conventions, which the engine API inherits.
//!
//! ```text
//!     0      -> "0x0"      the only form of zero
//!     1      -> "0x1"
//!     1024   -> "0x400"
//!     "0x"   -> rejected   no digits
//!     "0x0400" -> rejected leading zero
//!     "400"  -> rejected   no prefix
//! ```

use axiom_ssz::U256;

use crate::hex::{HexDigits, HexError};

/// An unsigned integer that the Ethereum JSON-RPC carries as a QUANTITY.
pub trait Quantity: Sized {
    /// The minimal 0x-prefixed lowercase hex of the value.
    #[must_use]
    fn to_quantity(&self) -> String;

    /// Decodes a QUANTITY.
    ///
    /// # Errors
    ///
    /// Fails on a missing prefix, no digits, a leading zero, a bad digit, or too many bits.
    fn from_quantity(text: &str) -> Result<Self, HexError>;
}

impl Quantity for u64 {
    fn to_quantity(&self) -> String {
        // The alternate hex format is exactly the QUANTITY form: 0x, lowercase, minimal.
        format!("{self:#x}")
    }

    fn from_quantity(text: &str) -> Result<Self, HexError> {
        let digits = HexDigits::new(text)?.quantity()?;
        // Sixteen hex digits hold 64 bits; a seventeenth significant digit cannot fit.
        if digits.len() > 16 {
            return Err(HexError::Overflow);
        }
        // Shift each digit in, most significant first.
        Ok(digits
            .iter()
            .fold(0, |value, &nibble| (value << 4) | Self::from(nibble)))
    }
}

impl Quantity for U256 {
    fn to_quantity(&self) -> String {
        // The integer is stored little-endian, so the most significant byte is last.
        let bytes = self.to_le_bytes();
        let Some(top) = bytes.iter().rposition(|&byte| byte != 0) else {
            // All 32 bytes are zero.
            return "0x0".to_owned();
        };

        let mut out = String::with_capacity(2 + 2 * (top + 1));
        out.push_str("0x");
        // The top byte drops its high nibble when that nibble is zero, so 0x0f is written "f".
        let high = bytes[top] >> 4;
        if high != 0 {
            HexDigits::push_nibble(&mut out, high);
        }
        HexDigits::push_nibble(&mut out, bytes[top] & 0xf);
        // Every lower byte is written in full, two digits, walking toward the least significant.
        for &byte in bytes[..top].iter().rev() {
            HexDigits::push_nibble(&mut out, byte >> 4);
            HexDigits::push_nibble(&mut out, byte & 0xf);
        }
        out
    }

    fn from_quantity(text: &str) -> Result<Self, HexError> {
        let digits = HexDigits::new(text)?.quantity()?;
        // Sixty-four hex digits hold 256 bits.
        if digits.len() > 64 {
            return Err(HexError::Overflow);
        }

        // Place nibbles from the least significant end.
        //
        //     "0x1234"  nibbles from the right: 4 3 2 1
        //     byte 0 = 0x34, byte 1 = 0x12   (little-endian storage)
        let mut bytes = [0_u8; 32];
        for (position, &nibble) in digits.iter().rev().enumerate() {
            bytes[position / 2] |= nibble << (4 * (position % 2));
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn u64_boundaries() {
        // Zero, one, and the largest value round-trip through their minimal forms.
        for (value, text) in [(0, "0x0"), (1, "0x1"), (u64::MAX, "0xffffffffffffffff")] {
            assert_eq!(value.to_quantity(), text);
            assert_eq!(u64::from_quantity(text), Ok(value));
        }
        // Uppercase digits decode, as the engine API's encoding pattern allows.
        assert_eq!(u64::from_quantity("0xFF"), Ok(255));
    }

    #[test]
    fn u64_rejections() {
        // Each malformed form maps to one error.
        assert_eq!(u64::from_quantity("ff"), Err(HexError::MissingPrefix));
        assert_eq!(u64::from_quantity("0Xff"), Err(HexError::MissingPrefix));
        assert_eq!(u64::from_quantity("0x"), Err(HexError::Empty));
        assert_eq!(u64::from_quantity("0x00"), Err(HexError::LeadingZero));
        assert_eq!(u64::from_quantity("0x0f"), Err(HexError::LeadingZero));
        assert_eq!(
            u64::from_quantity("0x1g"),
            Err(HexError::InvalidDigit { offset: 3 })
        );
        // 2^64 needs seventeen digits.
        assert_eq!(
            u64::from_quantity("0x10000000000000000"),
            Err(HexError::Overflow)
        );
    }

    #[test]
    fn u256_boundaries() {
        // 0x0f in the top used byte drops its high nibble: 0x0f01 is written "f01".
        let mut bytes = [0; 32];
        bytes[0] = 0x01;
        bytes[1] = 0x0f;
        assert_eq!(U256(bytes).to_quantity(), "0xf01");
        assert_eq!(U256::from_quantity("0xf01"), Ok(U256(bytes)));

        // Zero and the largest value.
        assert_eq!(U256::ZERO.to_quantity(), "0x0");
        assert_eq!(U256::from_quantity("0x0"), Ok(U256::ZERO));
        let max = format!("0x{}", "f".repeat(64));
        assert_eq!(U256::MAX.to_quantity(), max);
        assert_eq!(U256::from_quantity(&max), Ok(U256::MAX));

        // Sixty-five digits is past 256 bits.
        let over = format!("0x1{}", "0".repeat(64));
        assert_eq!(U256::from_quantity(&over), Err(HexError::Overflow));
    }

    proptest! {
        #[test]
        fn quantity_u64_round_trip(value in any::<u64>()) {
            // The minimal form decodes back and carries no leading zero.
            let text = value.to_quantity();
            prop_assert!(value == 0 || !text.starts_with("0x0"));
            prop_assert_eq!(u64::from_quantity(&text), Ok(value));
        }

        #[test]
        fn quantity_u256_round_trip(bytes in any::<[u8; 32]>()) {
            // Same law over 256 bits.
            let value = U256(bytes);
            prop_assert_eq!(U256::from_quantity(&value.to_quantity()), Ok(value));
        }

        #[test]
        fn quantity_widths_agree(value in any::<u64>()) {
            // A 64-bit value has the same text whether read as 64 or 256 bits.
            prop_assert_eq!(U256::from_u64(value).to_quantity(), value.to_quantity());
        }
    }
}
