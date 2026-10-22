//! The fixed-length SHA-3 hashes of FIPS 202, section 6.1.

use crate::keccak::sponge::{STATE_BYTES, Sponge};

/// The SHA-3 domain byte: the suffix bits 01, then the first pad bit.
const DOMAIN: u8 = 0x06;

/// An incremental SHA-3 hasher with a RATE-byte rate and a DIGEST-byte output.
///
/// The capacity is twice the output, so RATE + 2 * DIGEST fills the 200-byte state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha3<const RATE: usize, const DIGEST: usize> {
    /// The absorbing sponge.
    sponge: Sponge<RATE>,
}

/// SHA3-224: 144 bytes of rate.
pub type Sha3_224 = Sha3<144, 28>;

/// SHA3-256: 136 bytes of rate.
pub type Sha3_256 = Sha3<136, 32>;

/// SHA3-384: 104 bytes of rate.
pub type Sha3_384 = Sha3<104, 48>;

/// SHA3-512: 72 bytes of rate.
pub type Sha3_512 = Sha3<72, 64>;

impl<const RATE: usize, const DIGEST: usize> Sha3<RATE, DIGEST> {
    /// A hasher over no bytes yet.
    #[must_use]
    pub const fn new() -> Self {
        // FIPS 202, section 6.1: the capacity c is twice the digest length.
        const {
            assert!(RATE + 2 * DIGEST == STATE_BYTES);
        }
        Self {
            sponge: Sponge::new(),
        }
    }

    /// The digest of one byte string.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; DIGEST] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Feeds more bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    /// Pads, squeezes, and returns the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST] {
        // Every digest is shorter than its rate, so one squeeze suffices.
        let mut digest = [0; DIGEST];
        self.sponge.pad(DOMAIN).extract(&mut digest);
        digest
    }
}

impl<const RATE: usize, const DIGEST: usize> Default for Sha3<RATE, DIGEST> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn abc_for_every_digest_length() {
        // The "abc" examples published with FIPS 202.
        assert_eq!(
            Sha3_224::digest(b"abc").to_vec(),
            hex("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
        );
        assert_eq!(
            Sha3_256::digest(b"abc").to_vec(),
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
        assert_eq!(
            Sha3_384::digest(b"abc").to_vec(),
            hex(
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
                 98d88cea927ac7f539f1edf228376d25"
            )
        );
        assert_eq!(
            Sha3_512::digest(b"abc").to_vec(),
            hex(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
    }

    #[test]
    fn empty_message() {
        // The FIPS 202 example for the empty string under SHA3-256.
        assert_eq!(
            Sha3_256::digest(b"").to_vec(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
    }
}
