//! Fiat-Shamir transcripts: hashes of everything a prover sent, reduced to field elements.
//!
//! Each transcript starts with a 16-byte domain tag, so challenges of different protocols never collide.
//! The verifier derives the challenge itself, so a prover cannot choose it after the fact.

use axiom_bls12_381::Scalar;
use sha2::{Digest, Sha256};

/// A running SHA-256 transcript that ends in one challenge scalar.
#[derive(Clone, Debug)]
pub(crate) struct Transcript(Sha256);

impl Transcript {
    /// Starts a transcript under a protocol's domain tag.
    pub(crate) fn new(tag: &[u8; 16]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        Self(hasher)
    }

    /// Absorbs raw bytes.
    pub(crate) fn append(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.update(bytes);
    }

    /// Absorbs an integer as 8 big-endian bytes, the spec's encoding of lengths and indices.
    pub(crate) fn append_u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    /// Hashes the transcript and reduces the digest modulo r, as hash_to_bls_field does.
    ///
    /// The output is not uniform: some residues have three preimages, others two.
    /// Soundness only needs each value to be unlikely, and none has probability above 2^-254.
    pub(crate) fn challenge(self) -> Scalar {
        Scalar::from_bytes_be_reduced(&self.0.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_absorb_as_eight_big_endian_bytes() {
        // Appending 258 as an integer equals appending 00 00 00 00 00 00 01 02.
        let mut by_integer = Transcript::new(b"TEST_TAG________");
        by_integer.append_u64(258);
        let mut by_bytes = Transcript::new(b"TEST_TAG________");
        by_bytes.append([0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(by_integer.challenge(), by_bytes.challenge());
    }
}
