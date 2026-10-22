//! The trait every SSZ type implements.

use crate::{DecodeError, GeneralizedIndex, MerkleProof, Root};

/// Size of a merkle chunk, the unit the hash tree is built from.
///
/// SHA-256 digests are 32 bytes, so a chunk holds exactly one child root.
pub const BYTES_PER_CHUNK: usize = 32;

/// Size of an offset pointing at a variable-size part of an encoding.
///
/// Four bytes cap any single encoding at 4 GiB, which the spec accepts.
pub const BYTES_PER_LENGTH_OFFSET: usize = 4;

/// A type with an SSZ serialization and a hash tree root.
///
/// # Overview
///
/// Serialization and merkleization are two views of one schema.
/// They are one trait, because no consensus type ever has one without the other.
///
/// A type is fixed-size when every value encodes to the same number of bytes.
/// Containers and collections use that fact to lay out offsets.
///
/// # Invariants
///
/// Decoding the encoding of a value returns an equal value.
///
/// Decoding is strict: every byte string has at most one accepted interpretation.
/// That makes the encoding injective, so a signature over bytes is a signature over a value.
pub trait Ssz: Sized {
    /// Length of every encoding, when the type is fixed-size.
    const FIXED_SIZE: Option<usize>;

    /// Bytes per value when the type is basic.
    ///
    /// Basic values pack several to a chunk when merkleized in a collection.
    /// Composite types leave this empty, and contribute one root per value instead.
    const PACKED_SIZE: Option<usize> = None;

    /// Length of this value's encoding, in bytes.
    fn encoded_len(&self) -> usize;

    /// Appends this value's encoding to a buffer.
    fn encode_to(&self, out: &mut Vec<u8>);

    /// Decodes a value that spans exactly the given bytes.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of any value of this type.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;

    /// Merkle commitment to this value.
    fn hash_tree_root(&self) -> Root;

    /// This value's encoding, in a fresh buffer.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_to(&mut out);
        out
    }

    /// Proof for the node at a generalized index of this value's hash tree.
    ///
    /// Returns the node and the siblings from it up to the root, or nothing when the
    /// index does not address a node this type can prove.
    /// Every type proves its own root; containers also prove nodes inside their fields.
    fn prove(&self, index: GeneralizedIndex) -> Option<(Root, MerkleProof)> {
        (index == GeneralizedIndex::ROOT).then(|| (self.hash_tree_root(), MerkleProof::default()))
    }

    /// Whether the type is variable-size.
    #[must_use]
    fn is_variable_size() -> bool {
        Self::FIXED_SIZE.is_none()
    }
}
