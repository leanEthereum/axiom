//! Base58btc, the text form of peer identifiers.
//!
//! # Overview
//!
//! The bytes are read as one big-endian number and written in base 58.
//! The alphabet drops the look-alike characters `0`, `O`, `I`, and `l`.
//! Each leading zero byte becomes one leading `1`, so leading zeros survive.
//!
//! ```text
//! bytes [0x00, 0x00, 0x01]  →  "11" + base58(1) = "112"
//! ```
//!
//! The quadratic schoolbook conversion is fine for 40-byte identifiers.

use std::iter::repeat_n;

/// The Bitcoin base58 alphabet.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Longest input accepted by the decoder.
///
/// Identifiers are under 64 bytes, so a cap keeps the quadratic decoder cheap on hostile text.
const MAX_DECODED_LEN: usize = 256;

/// Encodes bytes as base58btc text.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
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
            .map(|&digit| char::from(ALPHABET[usize::from(digit)])),
    );
    text
}

/// Decodes base58btc text, or nothing when a character is outside the alphabet.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    // Hostile text cannot force more than a bounded amount of work.
    if text.len() > MAX_DECODED_LEN {
        return None;
    }
    // Phase 1: each leading '1' stands for one zero byte.
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    // Phase 2: base-58 to base-256, little-endian bytes.
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(zeros) {
        // Map the character back to its digit value.
        let digit = ALPHABET.iter().position(|&a| a == c)?;
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn known_vectors() {
        // Vectors from the base58 IETF draft.
        assert_eq!(encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(
            encode(b"The quick brown fox jumps over the lazy dog."),
            "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
        );
        // Two leading zero bytes become two leading '1's.
        assert_eq!(encode(&[0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]), "11233QC4");
        assert_eq!(
            decode("11233QC4"),
            Some(vec![0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd])
        );
        // The empty string is the empty byte string.
        assert_eq!(encode(&[]), "");
        assert_eq!(decode(""), Some(vec![]));
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // '0' is excluded from the alphabet as a look-alike of 'O'.
        assert_eq!(decode("10"), None);
        assert_eq!(decode("abc!"), None);
    }

    proptest! {
        #[test]
        fn round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }

        #[test]
        fn garbage_never_panics(text in "\\PC{0,80}") {
            let _ = decode(&text);
        }
    }
}
