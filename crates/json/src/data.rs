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

use crate::hex::{HexDigits, HexError};

/// Bytes that the Ethereum JSON-RPC carries as a DATA.
///
/// Any byte slice encodes.
/// Owned buffers and fixed-size arrays also decode.
pub trait Data {
    /// The 0x-prefixed lowercase hex of the bytes, two digits per byte.
    #[must_use]
    fn to_data(&self) -> String;

    /// Decodes a DATA.
    ///
    /// # Errors
    ///
    /// Fails on a missing prefix, an odd number of digits, a bad digit, or a wrong length.
    fn from_data(text: &str) -> Result<Self, HexError>
    where
        Self: Sized;
}

impl Data for [u8] {
    fn to_data(&self) -> String {
        let mut out = String::new();
        HexDigits::push_bytes(&mut out, self);
        out
    }
}

impl Data for Vec<u8> {
    fn to_data(&self) -> String {
        self.as_slice().to_data()
    }

    /// Decodes bytes of any length.
    fn from_data(text: &str) -> Result<Self, HexError> {
        let digits = HexDigits::new(text)?;
        let mut out = vec![0; digits.len() / 2];
        digits.bytes_into(&mut out)?;
        Ok(out)
    }
}

impl<const N: usize> Data for [u8; N] {
    fn to_data(&self) -> String {
        self.as_slice().to_data()
    }

    /// Decodes bytes of a length fixed by the type, such as a 32-byte hash.
    fn from_data(text: &str) -> Result<Self, HexError> {
        let mut out = [0; N];
        HexDigits::new(text)?.bytes_into(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_leading_zero_bytes() {
        // An empty byte string is the bare prefix.
        assert_eq!([].to_data(), "0x");
        assert_eq!(Vec::from_data("0x"), Ok(Vec::new()));

        // Unlike a quantity, leading zero bytes are significant and kept.
        assert_eq!([0x00, 0x41].to_data(), "0x0041");
        assert_eq!(Vec::from_data("0x0041"), Ok(vec![0x00, 0x41]));
    }

    #[test]
    fn rejections() {
        // Each malformed form maps to one error.
        assert_eq!(Vec::from_data("0041"), Err(HexError::MissingPrefix));
        assert_eq!(Vec::from_data("0x041"), Err(HexError::OddLength));
        assert_eq!(
            Vec::from_data("0x00zz"),
            Err(HexError::InvalidDigit { offset: 4 })
        );
        assert_eq!(
            Vec::from_data("0x0z"),
            Err(HexError::InvalidDigit { offset: 3 })
        );
    }

    #[test]
    fn fixed_length() {
        // Four bytes decode into a four-byte array; three do not.
        assert_eq!(
            <[u8; 4]>::from_data("0xdeadbeef"),
            Ok([0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(
            <[u8; 4]>::from_data("0xdeadbe"),
            Err(HexError::WrongLength {
                expected: 4,
                actual: 3
            })
        );
    }
}
