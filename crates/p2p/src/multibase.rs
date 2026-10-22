//! Multibase text encodings: the two forms a peer identifier is written in.
//!
//! # Overview
//!
//! Base58btc reads the bytes as one big-endian number and writes it in base 58.
//! The alphabet drops the look-alike characters `0`, `O`, `I`, and `l`.
//! Each leading zero byte becomes one leading `1`, so leading zeros survive.
//!
//! ```text
//! bytes [0x00, 0x00, 0x01]  →  "11" + base58(1) = "112"
//! ```
//!
//! Base32 is the unpadded lowercase alphabet of RFC 4648, five bits per character.
//!
//! The quadratic schoolbook base58 conversion is fine for 40-byte identifiers.
//! The multibase prefix character is left to the caller.
//! See `multiformats/multibase`.

use std::iter::repeat_n;

/// The Bitcoin base58 alphabet.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The RFC 4648 base32 alphabet, lowercase.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Longest base58 text the decoder accepts.
///
/// Identifiers are under 64 bytes, so a cap keeps the quadratic decoder cheap on hostile text.
const MAX_BASE58_LEN: usize = 256;

/// A multibase text encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Multibase {
    /// Base58 over the Bitcoin alphabet, multibase prefix `z`.
    Base58Btc,
    /// Unpadded lowercase RFC 4648 base32, multibase prefix `b`.
    Base32Lower,
}

impl Multibase {
    /// Encodes bytes as text.
    #[must_use]
    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Self::Base58Btc => Self::encode_base58(bytes),
            Self::Base32Lower => Self::encode_base32(bytes),
        }
    }

    /// Decodes text, or nothing when a character is outside the alphabet.
    #[must_use]
    pub fn decode(self, text: &str) -> Option<Vec<u8>> {
        match self {
            Self::Base58Btc => Self::decode_base58(text),
            Self::Base32Lower => Self::decode_base32(text),
        }
    }

    /// Base58btc encoding: repeated division of a big-endian number.
    fn encode_base58(bytes: &[u8]) -> String {
        // Phase 1: count the leading zero bytes, each one printed as the zero digit.
        let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
        // Phase 2: repeated base-256 to base-58 conversion, little-endian digits.
        //
        //     digits = n mod 58, (n / 58) mod 58, ...
        let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
        for &byte in &bytes[zeros..] {
            // Multiply the running number by 256 and add the byte.
            let mut carry = u32::from(byte);
            for digit in &mut digits {
                carry += u32::from(*digit) << 8;
                *digit = (carry % 58) as u8;
                carry /= 58;
            }
            // Spill the remaining carry into new high digits.
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        // Phase 3: print zero markers, then the digits most significant first.
        let mut text = String::with_capacity(zeros + digits.len());
        text.extend(repeat_n('1', zeros));
        text.extend(
            digits
                .iter()
                .rev()
                .map(|&digit| char::from(BASE58_ALPHABET[usize::from(digit)])),
        );
        text
    }

    /// Base58btc decoding: repeated multiplication into a big-endian number.
    fn decode_base58(text: &str) -> Option<Vec<u8>> {
        // Hostile text cannot force more than a bounded amount of work.
        if text.len() > MAX_BASE58_LEN {
            return None;
        }
        // Phase 1: each leading '1' stands for one zero byte.
        let zeros = text.bytes().take_while(|&c| c == b'1').count();
        // Phase 2: base-58 to base-256, little-endian bytes.
        let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
        for c in text.bytes().skip(zeros) {
            // Map the character back to its digit value.
            let digit = BASE58_ALPHABET.iter().position(|&a| a == c)?;
            // Multiply the running number by 58 and add the digit.
            let mut carry = digit as u32;
            for byte in &mut bytes {
                carry += u32::from(*byte) * 58;
                *byte = carry as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes.push(carry as u8);
                carry >>= 8;
            }
        }
        // Phase 3: restore the leading zeros, then flip to big-endian.
        let mut out = vec![0; zeros];
        out.extend(bytes.iter().rev());
        Some(out)
    }

    /// Base32 encoding: five bits per character, the last group padded with zero bits.
    fn encode_base32(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len().div_ceil(5) * 8);
        // Accumulate eight bits per byte, emitting whole five-bit groups.
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for &byte in bytes {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                text.push(char::from(
                    BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize],
                ));
            }
            // Keep only the bits not yet emitted, so the buffer never overflows.
            buffer &= (1 << bits) - 1;
        }
        // Left-align the leftover bits in one last group.
        if bits > 0 {
            text.push(char::from(
                BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
            ));
        }
        text
    }

    /// Base32 decoding: five bits per character, flushing whole bytes.
    ///
    /// Leftover bits that do not fill a byte are dropped.
    fn decode_base32(text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(text.len() * 5 / 8);
        // Accumulate five bits per character, flushing whole bytes.
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for c in text.bytes() {
            let value = BASE32_ALPHABET.iter().position(|&a| a == c)? as u32;
            buffer = (buffer << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
            // Keep only the bits not yet flushed, so the buffer never overflows.
            buffer &= (1 << bits) - 1;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn base58_known_vectors() {
        // Vectors from the base58 IETF draft.
        let base58 = Multibase::Base58Btc;
        assert_eq!(base58.encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(
            base58.encode(b"The quick brown fox jumps over the lazy dog."),
            "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
        );
        // Two leading zero bytes become two leading '1's.
        assert_eq!(
            base58.encode(&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]),
            "11233QC4"
        );
        assert_eq!(
            base58.decode("11233QC4"),
            Some(vec![0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd])
        );
        // The empty string is the empty byte string.
        assert_eq!(base58.encode(&[]), "");
        assert_eq!(base58.decode(""), Some(vec![]));
    }

    #[test]
    fn base32_known_vectors() {
        // RFC 4648 section 10, lowercased and unpadded: "foobar" → "mzxw6ytboi".
        let base32 = Multibase::Base32Lower;
        assert_eq!(base32.encode(b"f"), "my");
        assert_eq!(base32.encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32.decode("mzxw6ytboi"), Some(b"foobar".to_vec()));
        assert_eq!(base32.decode("my"), Some(b"f".to_vec()));
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // '0' is excluded from base58 as a look-alike of 'O'.
        assert_eq!(Multibase::Base58Btc.decode("10"), None);
        assert_eq!(Multibase::Base58Btc.decode("abc!"), None);
        // '1' is not a base32 digit, and neither are capitals.
        assert_eq!(Multibase::Base32Lower.decode("m1"), None);
        assert_eq!(Multibase::Base32Lower.decode("MY"), None);
    }

    proptest! {
        #[test]
        fn round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            for base in [Multibase::Base58Btc, Multibase::Base32Lower] {
                prop_assert_eq!(base.decode(&base.encode(&bytes)), Some(bytes.clone()));
            }
        }

        #[test]
        fn garbage_never_panics(text in "\\PC{0,80}") {
            let _ = Multibase::Base58Btc.decode(&text);
            let _ = Multibase::Base32Lower.decode(&text);
        }
    }
}
