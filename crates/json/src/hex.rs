//! Hex digits and the errors of the Ethereum hex encodings.

use thiserror::Error;

/// Lowercase digits, the form every execution client emits.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The digits of a hex string, after its mandatory 0x prefix.
///
/// Error offsets count from the start of the string, so they include the two prefix bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HexDigits<'a>(&'a [u8]);

impl<'a> HexDigits<'a> {
    /// Bytes of the prefix, which error offsets count.
    const PREFIX_LEN: usize = 2;

    /// The digits of a string, which must start with the 0x prefix.
    pub(crate) fn new(text: &'a str) -> Result<Self, HexError> {
        // Only a lowercase x is the Ethereum prefix; "0X" is rejected.
        text.as_bytes()
            .strip_prefix(b"0x")
            .map(Self)
            .ok_or(HexError::MissingPrefix)
    }

    /// Appends the 0x prefix and two lowercase digits per byte to a string.
    pub(crate) fn push_bytes(out: &mut String, bytes: &[u8]) {
        out.reserve(Self::PREFIX_LEN + 2 * bytes.len());
        out.push_str("0x");
        // High nibble first, then low nibble, for each byte.
        for &byte in bytes {
            Self::push_nibble(out, byte >> 4);
            Self::push_nibble(out, byte & 0xf);
        }
    }

    /// Appends the lowercase digit of a value below 16.
    pub(crate) fn push_nibble(out: &mut String, nibble: u8) {
        out.push(char::from(DIGITS[usize::from(nibble)]));
    }

    /// The value of one hex digit, in either case.
    ///
    /// The engine API's encoding rules allow either case on input.
    /// Encoders here emit lowercase only, as every execution client does.
    const fn value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    /// The value of the digit at an index, or the error naming its offset in the string.
    fn value_at(self, index: usize) -> Result<u8, HexError> {
        Self::value(self.0[index]).ok_or(HexError::InvalidDigit {
            offset: Self::PREFIX_LEN + index,
        })
    }

    /// Number of digits.
    pub(crate) const fn len(self) -> usize {
        self.0.len()
    }

    /// The digit values of a well-formed QUANTITY, most significant first.
    pub(crate) fn quantity(self) -> Result<Vec<u8>, HexError> {
        // "0x" alone carries no value; zero is written "0x0".
        if self.0.is_empty() {
            return Err(HexError::Empty);
        }
        // A zero first digit is allowed only when it is the whole number.
        if self.0.len() > 1 && self.0[0] == b'0' {
            return Err(HexError::LeadingZero);
        }
        (0..self.0.len())
            .map(|index| self.value_at(index))
            .collect()
    }

    /// Decodes DATA into a buffer that must match its length exactly.
    pub(crate) fn bytes_into(self, out: &mut [u8]) -> Result<(), HexError> {
        // Two digits per byte, so an odd count leaves half a byte.
        if !self.0.len().is_multiple_of(2) {
            return Err(HexError::OddLength);
        }
        // The length check precedes the digit scan, so a wrong-sized hash fails fast.
        if self.0.len() / 2 != out.len() {
            return Err(HexError::WrongLength {
                expected: out.len(),
                actual: self.0.len() / 2,
            });
        }
        for (index, byte) in out.iter_mut().enumerate() {
            let high = self.value_at(2 * index)?;
            let low = self.value_at(2 * index + 1)?;
            *byte = (high << 4) | low;
        }
        Ok(())
    }
}

/// A string that is not a valid QUANTITY or DATA.
///
/// Offsets count bytes from the start of the string, prefix included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum HexError {
    /// The string does not start with 0x.
    #[error("hex string lacks the 0x prefix")]
    MissingPrefix,

    /// A QUANTITY has no digits after the prefix.
    #[error("quantity has no digits")]
    Empty,

    /// A QUANTITY has a zero before its first significant digit.
    #[error("quantity has a leading zero")]
    LeadingZero,

    /// A DATA has an odd number of digits, so its last byte is half missing.
    #[error("data has an odd number of hex digits")]
    OddLength,

    /// A byte that is not a hex digit.
    #[error("invalid hex digit at byte {offset}")]
    InvalidDigit {
        /// Byte offset of the offending character.
        offset: usize,
    },

    /// A QUANTITY exceeds the width of its integer type.
    #[error("quantity overflows its integer type")]
    Overflow,

    /// A DATA decodes to a different number of bytes than its type holds.
    #[error("data holds {actual} bytes, expected {expected}")]
    WrongLength {
        /// Bytes the type holds.
        expected: usize,
        /// Bytes the string encodes.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use proptest::prelude::*;

    use crate::{Data, Quantity};

    proptest! {
        #[test]
        fn hex_decoders_never_panic(text in "(0x)?[0-9a-fA-Fg-z]{0,70}") {
            // Only the outcome's existence matters here.
            let _ = u64::from_quantity(&text);
            let _ = U256::from_quantity(&text);
            let _ = Vec::<u8>::from_data(&text);
            let _ = <[u8; 32]>::from_data(&text);
        }
    }
}
