//! HMAC-SHA256, the keyed hash under HKDF and RFC 6979 nonces.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::ct::{Mask, wipe};

/// Bytes in one SHA-256 input block, the width HMAC pads its key to.
const BLOCK_LEN: usize = 64;

/// Byte XORed into the padded key for the inner hash, per RFC 2104, section 2.
const IPAD: u8 = 0x36;

/// Byte XORed into the padded key for the outer hash, per RFC 2104, section 2.
const OPAD: u8 = 0x5c;

/// An incremental HMAC-SHA256 computation, per RFC 2104.
///
/// # Overview
///
/// ```text
/// HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
/// K'         = K zero-padded to 64 bytes, or H(K) zero-padded when K is longer
/// ```
///
/// Both hashes start from their keyed block at construction.
/// Feeding message bytes then only touches the inner hash.
///
/// # Examples
///
/// ```
/// use axiom_crypto::hmac::HmacSha256;
///
/// let mut mac = HmacSha256::new(b"key");
/// mac.update(b"message");
/// assert_eq!(mac.finalize(), HmacSha256::mac(b"key", b"message"));
/// ```
#[derive(Clone)]
pub struct HmacSha256 {
    /// SHA-256 that has absorbed the inner padded key, then the message so far.
    inner: Sha256,
    /// SHA-256 that has absorbed the outer padded key.
    outer: Sha256,
}

impl HmacSha256 {
    /// Bytes in a tag.
    pub const OUTPUT_LEN: usize = 32;

    /// A computation keyed with any number of bytes.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        // Phase 1: shrink a long key to its hash, then zero-pad to one block.
        let mut block = [0_u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            block[..Self::OUTPUT_LEN].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        // Phase 2: start the inner hash on K' ^ ipad.
        for byte in &mut block {
            *byte ^= IPAD;
        }
        let inner = Sha256::new_with_prefix(block);

        // Phase 3: turn K' ^ ipad into K' ^ opad and start the outer hash.
        for byte in &mut block {
            *byte ^= IPAD ^ OPAD;
        }
        let outer = Sha256::new_with_prefix(block);

        // The padded key is secret: clear the stack copy.
        wipe(&mut block);
        Self { inner, outer }
    }

    /// The tag of one message.
    #[must_use]
    pub fn mac(key: &[u8], message: &[u8]) -> [u8; Self::OUTPUT_LEN] {
        // One-shot form of new, update, finalize.
        let mut mac = Self::new(key);
        mac.update(message);
        mac.finalize()
    }

    /// Feeds more message bytes.
    pub fn update(&mut self, data: &[u8]) {
        // Message bytes feed the inner hash only.
        self.inner.update(data);
    }

    /// The tag of every byte fed so far.
    #[must_use]
    pub fn finalize(self) -> [u8; Self::OUTPUT_LEN] {
        // The outer hash wraps the inner digest.
        let Self { inner, mut outer } = self;
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    /// Checks the computed tag against an expected one in constant time.
    ///
    /// Every byte is compared, so the time does not reveal where a forgery first differs.
    #[must_use]
    pub fn verify(self, expected: &[u8; Self::OUTPUT_LEN]) -> bool {
        // Timing: every byte of both tags is compared.
        Mask::bytes_equal(&self.finalize(), expected).reveal()
    }
}

impl fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The midstates are keyed: never print them.
        f.debug_struct("HmacSha256").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc_4231_vectors() {
        // RFC 4231, section 4: test cases 1 to 7 for HMAC-SHA-256.
        //
        //     1-4 : keys shorter than a block
        //     5   : output truncated to 128 bits
        //     6-7 : a 131-byte key, hashed down before use
        let long_key = [0xaa; 131];
        let cases: [(&[u8], &[u8], &str); 6] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                &hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                &[0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &long_key,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, message, expected) in cases {
            assert_eq!(HmacSha256::mac(key, message).to_vec(), hex(expected));
        }

        // Test case 5 publishes only the leading 128 bits.
        let tag = HmacSha256::mac(&[0x0c; 20], b"Test With Truncation");
        assert_eq!(tag[..16].to_vec(), hex("a3b6167473100ee06e0c796c2955552b"));
    }

    #[test]
    fn verify_accepts_the_tag_and_rejects_a_flipped_bit() {
        // The genuine tag passes.
        let tag = HmacSha256::mac(b"key", b"message");
        let mut mac = HmacSha256::new(b"key");
        mac.update(b"message");
        assert!(mac.clone().verify(&tag));

        // Mutation: flip the last bit of the last byte.
        let mut forged = tag;
        forged[31] ^= 1;
        assert!(!mac.verify(&forged));
    }

    #[test]
    fn debug_hides_the_keyed_state() {
        // Only the type name prints, never midstate words.
        assert_eq!(
            format!("{:?}", HmacSha256::new(b"secret")),
            "HmacSha256 { .. }"
        );
    }

    proptest! {
        #[test]
        fn incremental_matches_one_shot(
            key in prop::collection::vec(any::<u8>(), 0..150),
            message in prop::collection::vec(any::<u8>(), 0..300),
            cut in any::<prop::sample::Index>(),
        ) {
            // Splitting the message anywhere gives the one-shot tag.
            let at = cut.index(message.len() + 1);
            let mut mac = HmacSha256::new(&key);
            mac.update(&message[..at]);
            mac.update(&message[at..]);
            prop_assert_eq!(mac.finalize(), HmacSha256::mac(&key, &message));
        }
    }
}
