//! Containers: heterogeneous records with named, ordered fields.
//!
//! # Overview
//!
//! A container is written once by hand, with no derive macro.
//! The implementor lists its fields three times, always in declaration order.
//!
//! - Their fixed sizes, as a constant.
//! - A walk over the fields, which drives encoding, length, and merkleization.
//! - A field-by-field decode.
//!
//! Every SSZ operation then follows from that description.

mod decoder;
mod layout;
mod visitors;

pub use decoder::FieldDecoder;
use layout::Layout;
use visitors::{
    FieldProver, FieldRoots, FixedPartWriter, LengthCounter, RootMerkleizer, VariablePartWriter,
};

use crate::{DecodeError, GeneralizedIndex, MerkleProof, Merkleizer, Root, Ssz};

/// A record of named fields, serialized and merkleized in declaration order.
///
/// Every container gets its SSZ implementation from this description.
///
/// # Invariants
///
/// The three field listings agree: same fields, same order, same types.
/// Debug builds check the sizes against the constant on every walk.
pub trait Container: Sized {
    /// Fixed size of each field in order, empty for a variable-size field.
    const FIELDS: &'static [Option<usize>];

    /// Shows every field to the visitor, in declaration order.
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V);

    /// Builds the container by decoding its fields in declaration order.
    ///
    /// # Errors
    ///
    /// Fails when any field fails to decode.
    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError>;

    /// Root of every field, in declaration order.
    ///
    /// These are the leaves of the container's hash tree.
    fn field_roots(&self) -> Vec<Root> {
        let mut roots = FieldRoots::new(Self::FIELDS.len());
        self.visit_fields(&mut roots);
        roots.into_roots()
    }

    /// Proof that a field's root sits at its leaf of the container's tree.
    ///
    /// # Panics
    ///
    /// Panics when the container has no field at that index.
    fn field_proof(&self, index: usize) -> MerkleProof {
        assert!(index < Self::FIELDS.len(), "field {index} does not exist");
        MerkleProof::generate(&self.field_roots(), Self::depth(), index)
    }

    /// Generalized index of a field within the container's tree.
    ///
    /// # Panics
    ///
    /// Panics when the container has no field at that index.
    #[must_use]
    fn field_index(index: usize) -> GeneralizedIndex {
        assert!(index < Self::FIELDS.len(), "field {index} does not exist");
        GeneralizedIndex::at(Self::depth(), index as u64)
    }

    /// Depth of the container's tree, with one leaf per field.
    #[must_use]
    fn depth() -> usize {
        Merkleizer::depth_for(Self::FIELDS.len())
    }
}

/// A walk over a container's fields.
///
/// Encoding, length counting, and merkleization are each one visitor.
/// The trait is sealed, because a container only ever meets the visitors of this crate.
pub trait FieldVisitor: visitors::Sealed {
    /// Visits the next field.
    fn field<T: Ssz>(&mut self, value: &T);
}

impl<C: Container> Ssz for C {
    const FIXED_SIZE: Option<usize> = Layout::new(C::FIELDS).fixed_size();

    fn encoded_len(&self) -> usize {
        let mut counter = LengthCounter::new(Layout::new(C::FIELDS));
        self.visit_fields(&mut counter);
        counter.total()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        // Phase 1: fixed fields inline, and an offset in place of each variable field.
        let start = out.len();
        let mut fixed = FixedPartWriter::new(out, Layout::new(C::FIELDS));
        self.visit_fields(&mut fixed);

        // Phase 2: variable fields, in order, right after the fixed part.
        let mut variable = VariablePartWriter::new(out);
        self.visit_fields(&mut variable);

        debug_assert_eq!(out.len() - start, self.encoded_len());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut fields = FieldDecoder::new(bytes, Layout::new(C::FIELDS))?;
        let value = C::decode_fields(&mut fields)?;
        fields.finish();
        Ok(value)
    }

    fn hash_tree_root(&self) -> Root {
        let mut merkleizer = RootMerkleizer::new(Layout::new(C::FIELDS));
        self.visit_fields(&mut merkleizer);
        merkleizer.finish()
    }

    /// Proves a node of the container's tree, descending into a field when the index is deeper.
    ///
    /// ```text
    /// index 169 in a 64-leaf container = 0b1_010100_1
    /// branch = [siblings inside the field] ++ [siblings of field 20 in the container]
    /// ```
    ///
    /// The six bits 010100 pick field 20, then the last bit picks node 1 inside it.
    fn prove(&self, index: GeneralizedIndex) -> Option<(Root, MerkleProof)> {
        if index == GeneralizedIndex::ROOT {
            return Some((self.hash_tree_root(), MerkleProof::default()));
        }
        let depth = Self::depth();
        if (index.depth() as usize) < depth {
            return None;
        }

        // Split the path: the top bits pick the field, the rest address a node inside it.
        let inner_depth = index.depth() as usize - depth;
        let field = (index.get() >> inner_depth) - (1 << depth);
        let inner =
            GeneralizedIndex::new((1 << inner_depth) | (index.get() & ((1 << inner_depth) - 1)));

        let mut prover = FieldProver::new(field as usize, inner);
        self.visit_fields(&mut prover);
        let (leaf, mut proof) = prover.into_result()?;
        proof.branch.extend(self.field_proof(field as usize).branch);
        Some((leaf, proof))
    }
}

#[cfg(test)]
mod tests;
