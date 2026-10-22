//! The hash functions that certificate and handshake signatures are computed over.

use sha2::{Digest, Sha256, Sha384, Sha512};

/// A SHA-2 hash function, per FIPS 180-4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256, 32 bytes of output.
    Sha256,
    /// SHA-384, 48 bytes of output.
    Sha384,
    /// SHA-512, 64 bytes of output.
    Sha512,
}

impl HashAlgorithm {
    /// Bytes of output.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The hash of a message.
    #[must_use]
    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_lengths_match_the_digests() {
        // FIPS 180-4: the empty message hashes to 32, 48 and 64 bytes.
        for hash in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ] {
            assert_eq!(hash.digest(b"").len(), hash.output_len());
        }
        // SHA-256 of "abc", from FIPS 180-4, appendix B.1, first and last bytes.
        let abc = HashAlgorithm::Sha256.digest(b"abc");
        assert_eq!((abc[0], abc[31]), (0xba, 0xad));
    }
}
