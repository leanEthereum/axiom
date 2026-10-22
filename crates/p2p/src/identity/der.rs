//! The DER form of an ECDSA signature, as Bitcoin and libp2p write it.
//!
//! ```text
//! 30 len                  SEQUENCE, short-form length
//!    02 len_r  r          INTEGER r, big-endian, minimal, non-negative
//!    02 len_s  s          INTEGER s, likewise
//!
//! r = 0x8f..., 32 bytes  →  02 21 00 8f ...    a leading zero keeps it positive
//! r = 0x00 7a..          →  02 1f 7a ...       leading zeros are stripped
//! ```
//!
//! See BIP 66 for the strict rules, and `libp2p/specs/peer-ids/peer-ids.md`.

use axiom_crypto::secp256k1::Signature;

/// ASN.1 tag of a SEQUENCE.
const SEQUENCE: u8 = 0x30;

/// ASN.1 tag of an INTEGER.
const INTEGER: u8 = 0x02;

/// Bytes of one scalar in the compact form.
const SCALAR_LEN: usize = 32;

/// A DER-encoded secp256k1 ECDSA signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerSignature(Vec<u8>);

impl DerSignature {
    /// The DER encoding of a signature.
    #[must_use]
    pub fn from_signature(signature: &Signature) -> Self {
        let compact = signature.to_bytes();
        let (r, s) = compact.split_at(SCALAR_LEN);
        let mut body = Vec::with_capacity(2 * (SCALAR_LEN + 3));
        Self::write_integer(r, &mut body);
        Self::write_integer(s, &mut body);

        // Invariant: two integers of at most 35 bytes each stay below the 128-byte short form.
        let mut der = Vec::with_capacity(body.len() + 2);
        der.push(SEQUENCE);
        der.push(body.len() as u8);
        der.extend_from_slice(&body);
        Self(der)
    }

    /// Wraps received bytes; nothing is checked until decoding.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The encoded bytes, consuming the wrapper.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Decodes under the strict rules of BIP 66.
    ///
    /// # Returns
    ///
    /// The signature, or nothing for any non-canonical or out-of-range encoding.
    #[must_use]
    pub fn to_signature(&self) -> Option<Signature> {
        // The outer SEQUENCE must span exactly the rest of the input.
        let (&tag, rest) = self.0.split_first()?;
        let (&len, body) = rest.split_first()?;
        if tag != SEQUENCE || usize::from(len) != body.len() {
            return None;
        }

        // Two integers, then nothing.
        let (r, body) = Self::read_integer(body)?;
        let (s, body) = Self::read_integer(body)?;
        if !body.is_empty() {
            return None;
        }

        // The compact form checks both scalars lie in [1, n).
        let mut compact = [0u8; 2 * SCALAR_LEN];
        compact[..SCALAR_LEN].copy_from_slice(&r);
        compact[SCALAR_LEN..].copy_from_slice(&s);
        Signature::from_bytes(&compact).ok()
    }

    /// Appends one big-endian scalar as a minimal, non-negative INTEGER.
    fn write_integer(scalar: &[u8], out: &mut Vec<u8>) {
        // Strip leading zeros, but keep one byte for the value zero.
        let first = scalar
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(scalar.len() - 1);
        let digits = &scalar[first..];

        // A set top bit would read as negative, so a zero byte goes in front.
        let pad = digits[0] & 0x80 != 0;
        out.push(INTEGER);
        out.push((digits.len() + usize::from(pad)) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(digits);
    }

    /// Reads one INTEGER into a 32-byte big-endian scalar.
    fn read_integer(bytes: &[u8]) -> Option<([u8; SCALAR_LEN], &[u8])> {
        let (&tag, rest) = bytes.split_first()?;
        let (&len, rest) = rest.split_first()?;
        let len = usize::from(len);
        if tag != INTEGER || len == 0 || rest.len() < len {
            return None;
        }
        let (digits, rest) = rest.split_at(len);

        // Negative values are invalid.
        if digits[0] & 0x80 != 0 {
            return None;
        }
        // A leading zero is allowed only to clear the sign bit of the next byte.
        if len > 1 && digits[0] == 0 && digits[1] & 0x80 == 0 {
            return None;
        }

        // Drop the sign byte, then right-align into 32 bytes.
        let digits = if digits[0] == 0 && len > 1 {
            &digits[1..]
        } else {
            digits
        };
        if digits.len() > SCALAR_LEN {
            return None;
        }
        let mut scalar = [0u8; SCALAR_LEN];
        scalar[SCALAR_LEN - digits.len()..].copy_from_slice(digits);
        Some((scalar, rest))
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::secp256k1::SecretKey;
    use proptest::prelude::*;

    use super::*;
    /// A signature with chosen compact bytes.
    fn signature(r: [u8; 32], s: [u8; 32]) -> Signature {
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&r);
        compact[32..].copy_from_slice(&s);
        Signature::from_bytes(&compact).unwrap()
    }

    #[test]
    fn high_bit_gets_a_sign_byte_and_zeros_are_stripped() {
        // r = 0x80 00 .. 01 needs a sign byte: 33 content bytes.
        let mut r = [0u8; 32];
        r[0] = 0x80;
        r[31] = 1;
        // s = 0x00 00 7f 00 .. 05 drops its two leading zeros: 30 content bytes.
        let mut s = [0u8; 32];
        s[2] = 0x7f;
        s[31] = 5;
        let der = DerSignature::from_signature(&signature(r, s));

        // 30 43 | 02 21 00 80..01 | 02 1e 7f..05: 2 header bytes and a 67-byte body.
        let bytes = der.as_bytes();
        assert_eq!(bytes.len(), 69);
        assert_eq!(&bytes[..5], &[0x30, 0x43, 0x02, 0x21, 0x00]);
        assert_eq!(bytes[5], 0x80);
        assert_eq!(&bytes[37..40], &[0x02, 0x1e, 0x7f]);
        assert_eq!(der.to_signature(), Some(signature(r, s)));
    }

    #[test]
    fn smallest_canonical_encoding_decodes() {
        // r = 1 and s = 1: one content byte each, 8 bytes in all.
        let der = DerSignature::from_bytes(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(der.to_signature(), Some(signature(one, one)));
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let refuse = |bytes: &[u8]| DerSignature::from_bytes(bytes.to_vec()).to_signature();

        // Mutation: r = 00 01 carries a superfluous leading zero.
        assert_eq!(
            refuse(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]),
            None
        );
        // Mutation: r = 0x81 has its sign bit set, so it reads as negative.
        assert_eq!(
            refuse(&[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01]),
            None
        );
        // Mutation: r = 0, outside [1, n).
        assert_eq!(
            refuse(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]),
            None
        );
        // Mutation: a trailing byte after the sequence.
        assert_eq!(
            refuse(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]),
            None
        );
        // Mutation: a SET tag 0x31 instead of SEQUENCE.
        assert_eq!(
            refuse(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            None
        );
        // Mutation: the outer length claims 7 bytes but 6 follow.
        assert_eq!(
            refuse(&[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            None
        );
        // Mutation: an empty INTEGER.
        assert_eq!(refuse(&[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01]), None);
        // An empty input.
        assert_eq!(refuse(&[]), None);
    }

    proptest! {
        #[test]
        fn round_trip(secret in any::<[u8; 32]>(), hash in any::<[u8; 32]>()) {
            let Ok(key) = SecretKey::from_bytes(&secret) else {
                return Ok(());
            };
            let signature = key.sign(&hash);
            let der = DerSignature::from_signature(&signature);
            prop_assert!(der.as_bytes().len() <= 72);
            prop_assert_eq!(der.to_signature(), Some(signature));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            let _ = DerSignature::from_bytes(bytes).to_signature();
        }
    }
}
