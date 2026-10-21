//! The node hash and the length mix-in.

use sha2::{Digest, Sha256};

use crate::{BYTES_PER_CHUNK, Root};

impl Root {
    /// Parent node of two children: the SHA-256 of their concatenation.
    #[must_use]
    pub fn hash_pair(left: &Self, right: &Self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(left.0);
        hasher.update(right.0);
        Self(hasher.finalize().into())
    }

    /// Mixes a collection's length into the root of its contents.
    ///
    /// Without it, a list and its zero-padded extension would share a root.
    ///
    /// ```text
    ///          root
    ///         /    \
    ///   contents   length as uint256
    /// ```
    #[must_use]
    pub fn mix_in_length(&self, length: usize) -> Self {
        let mut chunk = [0; BYTES_PER_CHUNK];
        chunk[..8].copy_from_slice(&(length as u64).to_le_bytes());
        Self::hash_pair(self, &Self(chunk))
    }

    /// Mixes a union's selector into the root of its value.
    #[must_use]
    pub fn mix_in_selector(&self, selector: u8) -> Self {
        Self::hash_pair(self, &Self::from_partial(&[selector]))
    }

    /// SHA-256 of arbitrary bytes, as a root.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_hash_is_sha256_of_concatenation() {
        // Two zero chunks hash to the well-known first zero-subtree root.
        let parent = Root::hash_pair(&Root::ZERO, &Root::ZERO);

        assert_eq!(
            parent.to_string(),
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        );
    }

    #[test]
    fn length_mix_in_hashes_with_little_endian_length() {
        // Length 3 becomes the chunk 03 00 .. 00 on the right of the pair.
        let contents = Root([7; 32]);

        assert_eq!(
            contents.mix_in_length(3),
            Root::hash_pair(&contents, &Root::from_partial(&[3]))
        );
    }
}
