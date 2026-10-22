//! URL-safe base64 without padding, the text form of node records.
//!
//! See RFC 4648, section 5, and EIP-778, "Text Encoding".

use thiserror::Error;

/// The URL-safe alphabet: `-` and `_` replace `+` and `/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The URL-safe base64 codec, strict on input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Base64Url;

impl Base64Url {
    /// Encodes bytes, omitting padding.
    #[must_use]
    pub fn encode(bytes: &[u8]) -> String {
        // Every 3 bytes become 4 symbols; a tail of 1 or 2 bytes becomes 2 or 3.
        let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let mut word = [0_u8; 3];
            word[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from_be_bytes([0, word[0], word[1], word[2]]);
            let symbols = chunk.len() + 1;
            for index in 0..symbols {
                let sextet = (bits >> (18 - 6 * index)) & 0x3f;
                text.push(char::from(ALPHABET[sextet as usize]));
            }
        }
        text
    }

    /// Decodes unpadded text.
    ///
    /// # Errors
    ///
    /// Fails on a symbol outside the alphabet, on padding, on a dangling single symbol,
    /// and on nonzero bits past the last byte, which would give one input two spellings.
    pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
        let symbols = text.as_bytes();
        // A lone trailing symbol carries 6 bits, not enough for a byte.
        if symbols.len() % 4 == 1 {
            return Err(Base64Error::InvalidLength(symbols.len()));
        }
        let mut bytes = Vec::with_capacity(symbols.len() * 3 / 4);
        for (chunk_index, chunk) in symbols.chunks(4).enumerate() {
            // Gather up to four sextets into the top of a 24-bit word.
            let mut bits = 0_u32;
            for (index, &symbol) in chunk.iter().enumerate() {
                let value = Self::sextet(symbol).ok_or(Base64Error::InvalidSymbol {
                    symbol,
                    position: 4 * chunk_index + index,
                })?;
                bits |= u32::from(value) << (18 - 6 * index);
            }
            // Two symbols make one byte, three make two, four make three.
            let produced = chunk.len() - 1;
            let word = bits.to_be_bytes();
            // Canonical: the bits below the last whole byte must be zero.
            let unused = 24 - 8 * produced;
            if bits & ((1 << unused) - 1) != 0 {
                return Err(Base64Error::NonCanonical);
            }
            bytes.extend_from_slice(&word[1..=produced]);
        }
        Ok(bytes)
    }

    /// The value of one symbol, absent outside the alphabet.
    const fn sextet(symbol: u8) -> Option<u8> {
        // Four contiguous ranges, then the two URL-safe symbols.
        match symbol {
            b'A'..=b'Z' => Some(symbol - b'A'),
            b'a'..=b'z' => Some(symbol - b'a' + 26),
            b'0'..=b'9' => Some(symbol - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
}

/// Text that is not unpadded URL-safe base64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Base64Error {
    /// A byte outside the URL-safe alphabet, padding included.
    #[error("byte 0x{symbol:02x} at position {position} is not base64url")]
    InvalidSymbol {
        /// The byte.
        symbol: u8,
        /// Its position in the text, counting from zero.
        position: usize,
    },

    /// A length that leaves one symbol dangling.
    #[error("base64url length {0} leaves a dangling symbol")]
    InvalidLength(usize),

    /// Nonzero bits past the last encoded byte.
    #[error("base64url has nonzero trailing bits")]
    NonCanonical,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648, section 10, with padding removed.
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in cases {
            assert_eq!(Base64Url::encode(bytes), text);
            assert_eq!(Base64Url::decode(text).as_deref(), Ok(bytes));
        }
        // 0xfb 0xff uses both URL-safe symbols.
        assert_eq!(Base64Url::encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn rfc4648_section9_examples() {
        // RFC 4648 section 9 spells these in plain base64 as "FPucA9l+", "FPucA9k=", "FPucAw==".
        // The URL-safe alphabet turns "+" into "-", and padding goes.
        let cases: [(&[u8], &str); 3] = [
            (&[0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e], "FPucA9l-"),
            (&[0x14, 0xfb, 0x9c, 0x03, 0xd9], "FPucA9k"),
            (&[0x14, 0xfb, 0x9c, 0x03], "FPucAw"),
        ];
        for (bytes, text) in cases {
            assert_eq!(Base64Url::encode(bytes), text);
            assert_eq!(Base64Url::decode(text).as_deref(), Ok(bytes));
        }
    }

    #[test]
    fn strictness() {
        // Padding is outside the alphabet: the first = sits at position 2.
        assert_eq!(
            Base64Url::decode("Zg=="),
            Err(Base64Error::InvalidSymbol {
                symbol: b'=',
                position: 2,
            })
        );
        // The standard alphabet's + is refused, here at position 0.
        assert_eq!(
            Base64Url::decode("+w"),
            Err(Base64Error::InvalidSymbol {
                symbol: b'+',
                position: 0,
            })
        );
        // Five symbols leave one dangling.
        assert_eq!(
            Base64Url::decode("Zm9vY"),
            Err(Base64Error::InvalidLength(5))
        );
        // "Zh" spells 0x66 with a stray low bit set.
        assert_eq!(Base64Url::decode("Zh"), Err(Base64Error::NonCanonical));
    }

    proptest! {
        #[test]
        fn round_trip(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            // Decoding an encoding returns the bytes.
            prop_assert_eq!(Base64Url::decode(&Base64Url::encode(&bytes)), Ok(bytes));
        }

        #[test]
        fn decode_never_panics(text in "[A-Za-z0-9_=+/-]{0,40}") {
            // Any decoded text re-encodes to itself.
            if let Ok(bytes) = Base64Url::decode(&text) {
                prop_assert_eq!(Base64Url::encode(&bytes), text);
            }
        }
    }
}
