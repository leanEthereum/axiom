//! Hex without a prefix, the encoding of keystore and deposit data fields.

use crate::keys::HexError;

/// Lowercase digits, indexed by nibble value.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Hex text with two digits per byte and no 0x prefix.
///
/// Decoding accepts either case, since some tools write checksummed addresses in mixed case.
/// Encoding writes lowercase.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BareHex;

impl BareHex {
    /// The lowercase hex of the bytes.
    pub(crate) fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(2 * bytes.len());
        // High nibble first, then low nibble.
        for &byte in bytes {
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
        out
    }

    /// The bytes of a hex string of any even length.
    pub(crate) fn decode(text: &str) -> Result<Vec<u8>, HexError> {
        let digits = text.as_bytes();
        if !digits.len().is_multiple_of(2) {
            return Err(HexError::OddLength {
                digits: digits.len(),
            });
        }
        let mut out = vec![0; digits.len() / 2];
        for (index, (byte, pair)) in out.iter_mut().zip(digits.as_chunks::<2>().0).enumerate() {
            let high = Self::nibble(pair[0], 2 * index)?;
            let low = Self::nibble(pair[1], 2 * index + 1)?;
            *byte = (high << 4) | low;
        }
        Ok(out)
    }

    /// The bytes of a hex string that must encode exactly N bytes.
    pub(crate) fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
        let bytes = Self::decode(text)?;
        <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| HexError::Length {
            expected: N,
            actual: bytes.len(),
        })
    }

    /// The value of one hex digit, at a byte offset the error reports.
    const fn nibble(digit: u8, offset: usize) -> Result<u8, HexError> {
        match digit {
            b'0'..=b'9' => Ok(digit - b'0'),
            b'a'..=b'f' => Ok(digit - b'a' + 10),
            b'A'..=b'F' => Ok(digit - b'A' + 10),
            _ => Err(HexError::InvalidDigit { offset }),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn mixed_case_decodes_and_encodes_lowercase() {
        // A checksummed address fragment, as deposit files may carry it.
        assert_eq!(BareHex::decode("cBB8").unwrap(), [0xcb, 0xb8]);
        assert_eq!(BareHex::encode(&[0xcb, 0xb8, 0x00]), "cbb800");
        assert_eq!(BareHex::decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn malformed_text_is_refused_with_its_position() {
        // Three digits leave the last byte half written.
        assert_eq!(
            BareHex::decode("abc"),
            Err(HexError::OddLength { digits: 3 })
        );
        // The prefix is not part of this encoding: x at offset 1 is no digit.
        assert_eq!(
            BareHex::decode("0x12"),
            Err(HexError::InvalidDigit { offset: 1 })
        );
        // Two bytes where four are required.
        assert_eq!(
            BareHex::decode_array::<4>("abcd"),
            Err(HexError::Length {
                expected: 4,
                actual: 2
            })
        );
    }

    proptest! {
        #[test]
        fn encoding_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(BareHex::decode(&BareHex::encode(&bytes)).unwrap(), bytes);
        }
    }
}
