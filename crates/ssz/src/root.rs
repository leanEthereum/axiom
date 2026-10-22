//! The 32-byte merkle root and the hashes that build trees of them.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::{BYTES_PER_CHUNK, DecodeError, Ssz};

/// A 32-byte merkle root.
///
/// It is both the output of merkleization and a chunk of the tree that produced it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Root(pub [u8; BYTES_PER_CHUNK]);

impl Root {
    /// The all-zero root, which is also the root of an empty subtree of depth zero.
    pub const ZERO: Self = Self([0; BYTES_PER_CHUNK]);

    /// Root over the given bytes, padded with zeros to a full chunk.
    ///
    /// # Panics
    ///
    /// Panics when the bytes are longer than a chunk.
    #[must_use]
    pub fn from_partial(bytes: &[u8]) -> Self {
        let mut chunk = [0; BYTES_PER_CHUNK];
        chunk[..bytes.len()].copy_from_slice(bytes);
        Self(chunk)
    }

    /// The root as a byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BYTES_PER_CHUNK] {
        &self.0
    }

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
    /// root = hash(contents root, length as uint256)
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

impl From<[u8; BYTES_PER_CHUNK]> for Root {
    fn from(bytes: [u8; BYTES_PER_CHUNK]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Root {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Root {
    /// Renders lowercase hex with a 0x prefix, the form the spec and its vectors use.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Ssz for Root {
    const FIXED_SIZE: Option<usize> = Some(BYTES_PER_CHUNK);

    fn encoded_len(&self) -> usize {
        BYTES_PER_CHUNK
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; BYTES_PER_CHUNK]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_prefixed_lowercase_hex() {
        // One distinctive byte at each end checks ordering and case.
        let mut bytes = [0; 32];
        bytes[0] = 0xab;
        bytes[31] = 0x0f;

        assert_eq!(
            Root(bytes).to_string(),
            "0xab0000000000000000000000000000000000000000000000000000000000000f"
        );
    }

    #[test]
    fn from_partial_pads_with_zeros() {
        // Three bytes fill the front of the chunk, and the other 29 stay zero.
        let root = Root::from_partial(&[1, 2, 3]);

        let mut expected = [0; 32];
        expected[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(root, Root(expected));
    }

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
