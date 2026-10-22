//! HMAC-SHA256, the MAC behind the HS256 signature of JWT.

use sha2::{Digest, Sha256};

/// Bytes in one SHA-256 input block, which sizes the HMAC key pads.
const BLOCK: usize = 64;

/// HMAC-SHA256 under one key, ready to authenticate messages.
///
/// # Algorithm
///
/// RFC 2104, with SHA-256 as the hash:
///
/// ```text
///     K'   = key, zero-padded to 64 bytes        (hashed first if longer than 64)
///     HMAC = SHA256( (K' ^ opad) || SHA256( (K' ^ ipad) || message ) )
///     ipad = 0x36 repeated, opad = 0x5c repeated
/// ```
///
/// The two pads differ in many bits, so the inner and outer keys are unrelated.
/// That blocks the length-extension attack a bare keyed hash would allow.
///
/// # Performance
///
/// Both padded key blocks are absorbed once, at construction.
/// Each message then costs its own hashing plus one block for the outer hash.
#[derive(Clone)]
pub(crate) struct HmacSha256 {
    /// The hash state after absorbing the key masked with 0x36.
    inner: Sha256,
    /// The hash state after absorbing the key masked with 0x5c.
    outer: Sha256,
}

impl HmacSha256 {
    /// Keys the MAC.
    pub(crate) fn new(key: &[u8]) -> Self {
        // A key longer than one block is replaced by its hash, per RFC 2104 section 2.
        let mut padded = [0_u8; BLOCK];
        if key.len() > BLOCK {
            padded[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            padded[..key.len()].copy_from_slice(key);
        }

        let mut inner = Sha256::new();
        inner.update(padded.map(|byte| byte ^ 0x36));
        let mut outer = Sha256::new();
        outer.update(padded.map(|byte| byte ^ 0x5c));
        Self { inner, outer }
    }

    /// Computes the tag of a message.
    pub(crate) fn mac(&self, message: &[u8]) -> [u8; 32] {
        // Inner hash over the masked key, then the message.
        let mut inner = self.inner.clone();
        inner.update(message);
        let inner = inner.finalize();

        // Outer hash over the other masked key, then the inner digest.
        let mut outer = self.outer.clone();
        outer.update(inner);
        outer.finalize().into()
    }

    /// Whether a tag authenticates a message, compared in time that depends only on lengths.
    ///
    /// A comparison that stops at the first difference leaks, through timing, how many leading bytes matched.
    /// An attacker could then forge a MAC one byte at a time.
    pub(crate) fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        let expected = self.mac(message);
        // Lengths are public: a MAC always has 32 bytes.
        if tag.len() != expected.len() {
            return false;
        }
        // Fold every byte difference into one accumulator, with no early exit.
        let difference = tag
            .iter()
            .zip(expected)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        difference == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("vector is hex"))
            .collect()
    }

    #[test]
    fn rfc4231_vectors() {
        // RFC 4231 section 4, the HMAC-SHA-256 outputs of test cases 1 to 4, 6, and 7.
        //
        //     case 1  20-byte key of 0x0b
        //     case 2  short ASCII key "Jefe"
        //     case 3  20-byte key of 0xaa, 50 bytes of 0xdd
        //     case 4  25-byte counting key, 50 bytes of 0xcd
        //     case 6  131-byte key, longer than a block, so it is hashed first
        //     case 7  131-byte key and a message longer than a block
        let long_key = vec![0xaa; 131];
        let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                (1..=25).collect(),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                long_key.clone(),
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                long_key,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, message, expected) in cases {
            assert_eq!(HmacSha256::new(&key).mac(&message).to_vec(), hex(expected));
        }
    }

    #[test]
    fn rfc4231_truncated_vector() {
        // Case 5 checks only the first 128 bits of the output.
        let mac = HmacSha256::new(&[0x0c; 20]).mac(b"Test With Truncation");
        assert_eq!(mac[..16].to_vec(), hex("a3b6167473100ee06e0c796c2955552b"));
    }

    #[test]
    fn verification() {
        // The tag of "abc" under the key "k" verifies.
        let key = HmacSha256::new(b"k");
        let mut tag = key.mac(b"abc");
        assert!(key.verify(b"abc", &tag));

        // The same tag fails for another message, and with its last byte flipped.
        assert!(!key.verify(b"abd", &tag));
        tag[31] ^= 1;
        assert!(!key.verify(b"abc", &tag));

        // A tag one byte short fails on its length alone.
        assert!(!key.verify(b"abc", &key.mac(b"abc")[..31]));
    }
}
