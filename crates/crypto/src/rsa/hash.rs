//! The hash functions RSA signatures may name, with their DigestInfo prefixes and MGF1.

use sha2::{Digest, Sha256, Sha384, Sha512};

/// A hash function of the SHA-2 family, as named by an RSA signature scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RsaHash {
    /// SHA-256, per FIPS 180-4.
    Sha256,
    /// SHA-384, per FIPS 180-4.
    Sha384,
    /// SHA-512, per FIPS 180-4.
    Sha512,
}

impl RsaHash {
    /// The digest length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The DER of the DigestInfo header that precedes the digest, per RFC 8017, section 9.2, note 1.
    ///
    /// It is a SEQUENCE of the algorithm identifier with NULL parameters, then an OCTET STRING header.
    #[must_use]
    pub const fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    /// The digest of the concatenation of several byte strings.
    pub(super) fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Sha256 => Self::digest_with::<Sha256>(parts),
            Self::Sha384 => Self::digest_with::<Sha384>(parts),
            Self::Sha512 => Self::digest_with::<Sha512>(parts),
        }
    }

    /// The digest under one concrete hasher.
    fn digest_with<H: Digest>(parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher = H::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().to_vec()
    }

    /// XORs the MGF1 mask of a seed into a byte string, per RFC 8017, appendix B.2.1.
    ///
    /// The mask is the concatenation of Hash(seed || counter) for counters 0, 1, 2, and so on.
    /// The counter is a 4-byte big-endian integer, and the last block is cut to length.
    pub(super) fn apply_mgf1(self, seed: &[u8], target: &mut [u8]) {
        for (counter, chunk) in (0_u32..).zip(target.chunks_mut(self.output_len())) {
            let block = self.digest(&[seed, &counter.to_be_bytes()]);
            for (byte, mask) in chunk.iter_mut().zip(block) {
                *byte ^= mask;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_lengths_announce_the_digest() {
        // The outer SEQUENCE length counts every byte after its header, and the OCTET STRING the digest.
        for hash in [RsaHash::Sha256, RsaHash::Sha384, RsaHash::Sha512] {
            let prefix = hash.digest_info_prefix();
            assert_eq!(prefix.len(), 19);
            assert_eq!(usize::from(prefix[1]), prefix.len() - 2 + hash.output_len());
            assert_eq!(usize::from(prefix[18]), hash.output_len());
            assert_eq!(hash.digest(&[b"abc"]).len(), hash.output_len());
        }
    }

    #[test]
    fn mgf1_spans_blocks() {
        // A 40-byte SHA-256 mask is block 0 whole, then the first 8 bytes of block 1.
        let mut mask = [0_u8; 40];
        RsaHash::Sha256.apply_mgf1(b"seed", &mut mask);
        let block0 = RsaHash::Sha256.digest(&[b"seed", &[0, 0, 0, 0]]);
        let block1 = RsaHash::Sha256.digest(&[b"seed", &[0, 0, 0, 1]]);
        assert_eq!(mask[..32], block0[..]);
        assert_eq!(mask[32..], block1[..8]);

        // Applying the mask twice restores the input.
        RsaHash::Sha256.apply_mgf1(b"seed", &mut mask);
        assert_eq!(mask, [0; 40]);
    }
}
