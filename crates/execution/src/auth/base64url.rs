//! Base64url without padding, the encoding of every JWT segment.
//!
//! RFC 4648 section 5 swaps the two symbols of base64 that are unsafe in URLs.
//! RFC 7515 section 2 then drops the padding.
//!
//! ```text
//!     bytes   0x66      0x6f      0x6f        "foo"
//!     bits    01100110  01101111  01101111
//!     6-bit   011001 100110 111101 101111
//!     symbols Z      m      9      v          "Zm9v"
//! ```

use std::fmt::{self, Write};

/// The 64 symbols of the URL-safe alphabet, by value.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Bytes written as unpadded base64url.
///
/// Displaying the value encodes it; decoding goes the other way, from text.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Base64Url<'a>(pub(crate) &'a [u8]);

impl Base64Url<'_> {
    /// Decodes text without padding, accepting only the canonical encoding.
    ///
    /// Canonical means the unused low bits of the last symbol are zero.
    /// Otherwise two texts would decode to the same bytes, and a token could be altered unseen.
    pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
        let symbols = text.as_bytes();
        // A single leftover symbol carries six bits, less than one byte.
        if symbols.len() % 4 == 1 {
            return None;
        }

        let mut out = Vec::with_capacity(symbols.len() / 4 * 3 + 2);
        let (groups, tail) = symbols.as_chunks::<4>();
        for group in groups {
            // Four symbols carry 24 bits, three bytes.
            let word = group.iter().try_fold(0_u32, |word, &symbol| {
                Some(word << 6 | Self::value(symbol)?)
            })?;
            out.extend_from_slice(&word.to_be_bytes()[1..]);
        }

        if !tail.is_empty() {
            // Two symbols carry one byte plus 4 spare bits; three carry two bytes plus 2.
            let word = tail.iter().try_fold(0_u32, |word, &symbol| {
                Some(word << 6 | Self::value(symbol)?)
            })?;
            let spare_bits = 6 * tail.len() % 8;
            if word & ((1 << spare_bits) - 1) != 0 {
                return None;
            }
            let word = word >> spare_bits;
            let bytes = tail.len() - 1;
            out.extend_from_slice(&word.to_be_bytes()[4 - bytes..]);
        }
        Some(out)
    }

    /// The value of one symbol, or nothing for a byte outside the alphabet.
    const fn value(symbol: u8) -> Option<u32> {
        let value = match symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'a'..=b'z' => symbol - b'a' + 26,
            b'0'..=b'9' => symbol - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        Some(value as u32)
    }
}

impl fmt::Display for Base64Url<'_> {
    /// Encodes the bytes without padding.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = |word: u32, shift: u32| char::from(ALPHABET[(word >> shift & 0x3f) as usize]);
        let (groups, tail) = self.0.as_chunks::<3>();

        // Every three bytes become four symbols.
        for &[a, b, c] in groups {
            let word = u32::from_be_bytes([0, a, b, c]);
            for shift in [18, 12, 6, 0] {
                f.write_char(symbol(word, shift))?;
            }
        }

        // One leftover byte yields two symbols, two yield three; padding is omitted.
        let word = match *tail {
            [a] => u32::from_be_bytes([0, a, 0, 0]),
            [a, b] => u32::from_be_bytes([0, a, b, 0]),
            _ => return Ok(()),
        };
        for shift in [18, 12, 6].into_iter().take(tail.len() + 1) {
            f.write_char(symbol(word, shift))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..100)) {
            // Every byte string comes back, from ceil(4n / 3) symbols.
            let text = Base64Url(&bytes).to_string();
            prop_assert_eq!(text.len(), (4 * bytes.len()).div_ceil(3));
            prop_assert_eq!(Base64Url::decode(&text), Some(bytes));
        }

        #[test]
        fn decoding_is_canonical(text in "[A-Za-z0-9_-]{0,20}") {
            // Whatever decodes must encode back to the same text, so no two texts share bytes.
            if let Some(bytes) = Base64Url::decode(&text) {
                prop_assert_eq!(Base64Url(&bytes).to_string(), text);
            }
        }
    }

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 section 10, without the padding JWT omits.
        let cases = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in cases {
            assert_eq!(Base64Url(bytes.as_bytes()).to_string(), text);
            assert_eq!(Base64Url::decode(text), Some(bytes.as_bytes().to_vec()));
        }
    }

    #[test]
    fn url_safe_symbols() {
        // 0xfb 0xff encodes to the two symbols that differ from plain base64.
        //
        //     11111011 11111111 -> 111110 111111 1111(00) -> "-", "_", "8"
        assert_eq!(Base64Url(&[0xfb, 0xff]).to_string(), "-_8");
        assert_eq!(Base64Url::decode("-_8"), Some(vec![0xfb, 0xff]));
    }

    #[test]
    fn rejections() {
        // Padding, a plain-base64 symbol, one stray symbol, and nonzero spare bits.
        assert_eq!(Base64Url::decode("Zg=="), None);
        assert_eq!(Base64Url::decode("Zm+v"), None);
        assert_eq!(Base64Url::decode("Zm9vY"), None);
        // "Zh" holds 0x66 plus spare bits 0001, which must be zero.
        assert_eq!(Base64Url::decode("Zh"), None);
    }
}
