//! HMAC over SHA-256 and SHA-512, the keyed hashes under HKDF, PBKDF2, and RFC 6979 nonces.

use std::fmt;

use sha2::{
    Sha256, Sha512,
    digest::{
        Digest, Output,
        core_api::{Block, BlockSizeUser},
    },
};

use crate::ct::{Mask, wipe};

/// Byte XORed into the padded key for the inner hash, per RFC 2104, section 2.
const IPAD: u8 = 0x36;

/// Byte XORed into the padded key for the outer hash, per RFC 2104, section 2.
const OPAD: u8 = 0x5c;

/// An incremental HMAC computation over any block hash, per RFC 2104.
///
/// # Overview
///
/// ```text
/// HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
/// K'         = K zero-padded to one block, or H(K) zero-padded when K is longer
/// ```
///
/// Both hashes start from their keyed block at construction.
/// Feeding message bytes then only touches the inner hash.
/// A clone of a fresh computation restarts from the keyed midstates without rehashing the key.
#[derive(Clone)]
pub(crate) struct Hmac<H> {
    /// Hash that has absorbed the inner padded key, then the message so far.
    inner: H,
    /// Hash that has absorbed the outer padded key.
    outer: H,
}

impl<H: Digest + BlockSizeUser + Clone> Hmac<H> {
    /// A computation keyed with any number of bytes.
    pub(crate) fn new(key: &[u8]) -> Self {
        // Phase 1: shrink a long key to its hash, then zero-pad to one block.
        //
        //     SHA-256: 64-byte block, 32-byte digest
        //     SHA-512: 128-byte block, 64-byte digest
        //
        // A digest is always shorter than a block, so it fits.
        let mut block = Block::<H>::default();
        if key.len() > block.len() {
            let mut digest = H::digest(key);
            block[..digest.len()].copy_from_slice(&digest);
            wipe(digest.as_mut_slice());
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        // Phase 2: start the inner hash on K' ^ ipad.
        for byte in &mut block {
            *byte ^= IPAD;
        }
        let inner = H::new_with_prefix(&block);

        // Phase 3: turn K' ^ ipad into K' ^ opad and start the outer hash.
        for byte in &mut block {
            *byte ^= IPAD ^ OPAD;
        }
        let outer = H::new_with_prefix(&block);

        // The padded key is secret: clear the stack copy.
        wipe(block.as_mut_slice());
        Self { inner, outer }
    }

    /// Feeds more message bytes.
    pub(crate) fn update(&mut self, data: &[u8]) {
        // Message bytes feed the inner hash only.
        self.inner.update(data);
    }

    /// The tag of every byte fed so far.
    pub(crate) fn finalize(self) -> Output<H> {
        // The outer hash wraps the inner digest.
        let Self { inner, mut outer } = self;
        outer.update(inner.finalize());
        outer.finalize()
    }
}

/// An incremental HMAC-SHA256 computation, per RFC 2104.
#[derive(Clone)]
pub struct HmacSha256 {
    /// The keyed computation.
    hmac: Hmac<Sha256>,
}

impl HmacSha256 {
    /// Bytes in a tag.
    pub const OUTPUT_LEN: usize = 32;

    /// A computation keyed with any number of bytes.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self {
            hmac: Hmac::new(key),
        }
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
        self.hmac.update(data);
    }

    /// The tag of every byte fed so far.
    #[must_use]
    pub fn finalize(self) -> [u8; Self::OUTPUT_LEN] {
        self.hmac.finalize().into()
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

/// An incremental HMAC-SHA512 computation, per RFC 2104.
#[derive(Clone)]
pub struct HmacSha512 {
    /// The keyed computation.
    hmac: Hmac<Sha512>,
}

impl HmacSha512 {
    /// Bytes in a tag.
    pub const OUTPUT_LEN: usize = 64;

    /// A computation keyed with any number of bytes.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self {
            hmac: Hmac::new(key),
        }
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
        self.hmac.update(data);
    }

    /// The tag of every byte fed so far.
    #[must_use]
    pub fn finalize(self) -> [u8; Self::OUTPUT_LEN] {
        self.hmac.finalize().into()
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

impl fmt::Debug for HmacSha512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The midstates are keyed: never print them.
        f.debug_struct("HmacSha512").finish_non_exhaustive()
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
    fn rfc_4231_sha256_vectors() {
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
    fn rfc_4231_sha512_vectors() {
        // RFC 4231, section 4: test cases 1 to 7 for HMAC-SHA-512.
        //
        //     1-4 : keys shorter than the 128-byte block
        //     5   : output truncated to 128 bits
        //     6-7 : a 131-byte key, one byte over the block, hashed down before use
        let long_key = [0xaa; 131];
        let cases: [(&[u8], &[u8], &str); 6] = [
            (
                &[0x0b; 20],
                b"Hi There",
                concat!(
                    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
                ),
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                concat!(
                    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
                ),
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                concat!(
                    "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
                    "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
                ),
            ),
            (
                &hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                &[0xcd; 50],
                concat!(
                    "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db",
                    "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
                ),
            ),
            (
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                concat!(
                    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
                    "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
                ),
            ),
            (
                &long_key,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                concat!(
                    "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944",
                    "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
                ),
            ),
        ];
        for (key, message, expected) in cases {
            assert_eq!(HmacSha512::mac(key, message).to_vec(), hex(expected));
        }

        // Test case 5 publishes only the leading 128 bits.
        let tag = HmacSha512::mac(&[0x0c; 20], b"Test With Truncation");
        assert_eq!(tag[..16].to_vec(), hex("415fad6271580a531d4179bc891d87a6"));
    }

    #[test]
    fn sha512_key_of_exactly_one_block_is_not_hashed() {
        // Threshold: a 128-byte key fills the SHA-512 block and is used as is.
        // The same key hashed first would give a different tag, so the two branches differ.
        let key = [0x42_u8; 128];
        let hashed = Sha512::digest(key);
        assert_ne!(HmacSha512::mac(&key, b"m"), HmacSha512::mac(&hashed, b"m"));

        // One byte more crosses the threshold: the key and its digest give the same tag.
        let long = [0x42_u8; 129];
        assert_eq!(
            HmacSha512::mac(&long, b"m"),
            HmacSha512::mac(&Sha512::digest(long), b"m")
        );
    }

    #[test]
    fn verify_accepts_the_tag_and_rejects_a_flipped_bit() {
        // The genuine 32-byte tag passes.
        let tag = HmacSha256::mac(b"key", b"message");
        let mut mac = HmacSha256::new(b"key");
        mac.update(b"message");
        assert!(mac.clone().verify(&tag));

        // Mutation: flip the last bit of the last byte.
        let mut forged = tag;
        forged[31] ^= 1;
        assert!(!mac.verify(&forged));

        // The same holds for the 64-byte tag, flipping bit 0 of byte 63.
        let tag = HmacSha512::mac(b"key", b"message");
        let mut mac = HmacSha512::new(b"key");
        mac.update(b"message");
        assert!(mac.clone().verify(&tag));
        let mut forged = tag;
        forged[63] ^= 1;
        assert!(!mac.verify(&forged));
    }

    #[test]
    fn debug_hides_the_keyed_state() {
        // Only the type name prints, never midstate words.
        assert_eq!(
            format!("{:?}", HmacSha256::new(b"secret")),
            "HmacSha256 { .. }"
        );
        assert_eq!(
            format!("{:?}", HmacSha512::new(b"secret")),
            "HmacSha512 { .. }"
        );
    }

    proptest! {
        #[test]
        fn incremental_matches_one_shot(
            key in prop::collection::vec(any::<u8>(), 0..300),
            message in prop::collection::vec(any::<u8>(), 0..300),
            cut in any::<prop::sample::Index>(),
        ) {
            // Splitting the message anywhere gives the one-shot tag, for both widths.
            let at = cut.index(message.len() + 1);
            let mut mac = HmacSha256::new(&key);
            mac.update(&message[..at]);
            mac.update(&message[at..]);
            prop_assert_eq!(mac.finalize(), HmacSha256::mac(&key, &message));

            let mut mac = HmacSha512::new(&key);
            mac.update(&message[..at]);
            mac.update(&message[at..]);
            prop_assert_eq!(mac.finalize(), HmacSha512::mac(&key, &message));
        }
    }
}
