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

use crate::hex::{DIGITS, HexError, digit, strip_prefix};

/// Encodes an unsigned 64-bit integer.
#[must_use]
pub fn encode(value: u64) -> String {
    // The alternate hex format is exactly the QUANTITY form: 0x, lowercase, minimal.
    format!("{value:#x}")
}

/// Decodes an unsigned 64-bit integer.
///
/// # Errors
///
/// Fails on a missing prefix, no digits, a leading zero, a bad digit, or more than 64 bits.
pub fn decode(text: &str) -> Result<u64, HexError> {
    let digits = checked_digits(text)?;
    // Sixteen hex digits hold 64 bits; a seventeenth significant digit cannot fit.
    if digits.len() > 16 {
        return Err(HexError::Overflow);
    }
    // Shift each digit in, most significant first.
    Ok(digits
        .iter()
        .fold(0, |value, &nibble| (value << 4) | u64::from(nibble)))
}

/// Encodes an unsigned 256-bit integer.
#[must_use]
pub fn encode_u256(value: &U256) -> String {
    // The integer is stored little-endian, so the most significant byte is last.
    let bytes = value.to_le_bytes();
    let Some(top) = bytes.iter().rposition(|&byte| byte != 0) else {
        // All 32 bytes are zero.
        return "0x0".to_owned();
    };

    let mut out = String::with_capacity(2 + 2 * (top + 1));
    out.push_str("0x");
    // The top byte drops its high nibble when that nibble is zero, so 0x0f is written "f".
    let high = bytes[top] >> 4;
    if high != 0 {
        out.push(char::from(DIGITS[usize::from(high)]));
    }
    out.push(char::from(DIGITS[usize::from(bytes[top] & 0xf)]));
    // Every lower byte is written in full, two digits, walking toward the least significant.
    for &byte in bytes[..top].iter().rev() {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// Decodes an unsigned 256-bit integer.
///
/// # Errors
///
/// Fails on a missing prefix, no digits, a leading zero, a bad digit, or more than 256 bits.
pub fn decode_u256(text: &str) -> Result<U256, HexError> {
    let digits = checked_digits(text)?;
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
    Ok(U256(bytes))
}

/// The digit values of a well-formed QUANTITY.
fn checked_digits(text: &str) -> Result<Vec<u8>, HexError> {
    let digits = strip_prefix(text)?;
    // "0x" alone carries no value; zero is written "0x0".
    if digits.is_empty() {
        return Err(HexError::Empty);
    }
    // A zero first digit is allowed only when it is the whole number.
    if digits.len() > 1 && digits[0] == b'0' {
        return Err(HexError::LeadingZero);
    }
    // Map each character to its value; offsets count the two prefix bytes.
    digits
        .iter()
        .enumerate()
        .map(|(index, &byte)| digit(byte).ok_or(HexError::InvalidDigit { offset: index + 2 }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_boundaries() {
        // Zero, one, and the largest value round-trip through their minimal forms.
        for (value, text) in [(0, "0x0"), (1, "0x1"), (u64::MAX, "0xffffffffffffffff")] {
            assert_eq!(encode(value), text);
            assert_eq!(decode(text), Ok(value));
        }
        // Uppercase digits decode, as the engine API's encoding pattern allows.
        assert_eq!(decode("0xFF"), Ok(255));
    }

    #[test]
    fn u64_rejections() {
        // Each malformed form maps to one error.
        assert_eq!(decode("ff"), Err(HexError::MissingPrefix));
        assert_eq!(decode("0Xff"), Err(HexError::MissingPrefix));
        assert_eq!(decode("0x"), Err(HexError::Empty));
        assert_eq!(decode("0x00"), Err(HexError::LeadingZero));
        assert_eq!(decode("0x0f"), Err(HexError::LeadingZero));
        assert_eq!(decode("0x1g"), Err(HexError::InvalidDigit { offset: 3 }));
        // 2^64 needs seventeen digits.
        assert_eq!(decode("0x10000000000000000"), Err(HexError::Overflow));
    }

    #[test]
    fn u256_boundaries() {
        // 0x0f in the top used byte drops its high nibble: 0x0f01 is written "f01".
        let mut bytes = [0; 32];
        bytes[0] = 0x01;
        bytes[1] = 0x0f;
        assert_eq!(encode_u256(&U256(bytes)), "0xf01");
        assert_eq!(decode_u256("0xf01"), Ok(U256(bytes)));

        // Zero and the largest value.
        assert_eq!(encode_u256(&U256::ZERO), "0x0");
        assert_eq!(decode_u256("0x0"), Ok(U256::ZERO));
        let max = format!("0x{}", "f".repeat(64));
        assert_eq!(encode_u256(&U256::MAX), max);
        assert_eq!(decode_u256(&max), Ok(U256::MAX));

        // Sixty-five digits is past 256 bits.
        let over = format!("0x1{}", "0".repeat(64));
        assert_eq!(decode_u256(&over), Err(HexError::Overflow));
    }
}
