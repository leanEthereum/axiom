//! DATA: bytes as 0x-prefixed hex, two digits per byte.
//!
//! The encoding comes from the Ethereum JSON-RPC conventions, which the engine API inherits.
//!
//! ```text
//!     []           -> "0x"
//!     [0x00, 0x41] -> "0x0041"     leading zero bytes are kept
//!     "0x041"      -> rejected     odd digit count
//!     "0041"       -> rejected     no prefix
//! ```

use crate::hex::{DIGITS, HexError, digit, strip_prefix};

/// Encodes bytes.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    // High nibble first, then low nibble, for each byte.
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// Decodes bytes of any length.
///
/// # Errors
///
/// Fails on a missing prefix, an odd number of digits, or a bad digit.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    let digits = strip_prefix(text)?;
    let mut out = vec![0; digits.len() / 2];
    decode_digits(digits, &mut out)?;
    Ok(out)
}

/// Decodes bytes of a length fixed by the type, such as a 32-byte hash.
///
/// # Errors
///
/// Fails like the variable-length decode, and when the length differs.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let digits = strip_prefix(text)?;
    let mut out = [0; N];
    decode_digits(digits, &mut out)?;
    Ok(out)
}

/// Decodes digits into a buffer that must match their length exactly.
fn decode_digits(digits: &[u8], out: &mut [u8]) -> Result<(), HexError> {
    // Two digits per byte, so an odd count leaves half a byte.
    if !digits.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    // The length check precedes the digit scan, so a wrong-sized hash fails fast.
    if digits.len() / 2 != out.len() {
        return Err(HexError::WrongLength {
            expected: out.len(),
            actual: digits.len() / 2,
        });
    }
    // Pair up digits; offsets count the two prefix bytes.
    let (pairs, _) = digits.as_chunks::<2>();
    for (index, (pair, byte)) in pairs.iter().zip(out.iter_mut()).enumerate() {
        let high = digit(pair[0]).ok_or(HexError::InvalidDigit {
            offset: 2 + 2 * index,
        })?;
        let low = digit(pair[1]).ok_or(HexError::InvalidDigit {
            offset: 3 + 2 * index,
        })?;
        *byte = (high << 4) | low;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_leading_zero_bytes() {
        // An empty byte string is the bare prefix.
        assert_eq!(encode(&[]), "0x");
        assert_eq!(decode("0x"), Ok(Vec::new()));

        // Unlike a quantity, leading zero bytes are significant and kept.
        assert_eq!(encode(&[0x00, 0x41]), "0x0041");
        assert_eq!(decode("0x0041"), Ok(vec![0x00, 0x41]));
    }

    #[test]
    fn rejections() {
        // Each malformed form maps to one error.
        assert_eq!(decode("0041"), Err(HexError::MissingPrefix));
        assert_eq!(decode("0x041"), Err(HexError::OddLength));
        assert_eq!(decode("0x00zz"), Err(HexError::InvalidDigit { offset: 4 }));
        assert_eq!(decode("0x0z"), Err(HexError::InvalidDigit { offset: 3 }));
    }

    #[test]
    fn fixed_length() {
        // Four bytes decode into a four-byte array; three do not.
        assert_eq!(
            decode_array::<4>("0xdeadbeef"),
            Ok([0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(
            decode_array::<4>("0xdeadbe"),
            Err(HexError::WrongLength {
                expected: 4,
                actual: 3
            })
        );
    }
}
