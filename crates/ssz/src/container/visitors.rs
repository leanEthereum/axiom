//! The visitors that turn a field walk into each SSZ operation.

use super::{FieldTree, Layout};
use crate::{
    BYTES_PER_LENGTH_OFFSET, FieldVisitor, GeneralizedIndex, MerkleProof, Root, Ssz, offset::Offset,
};

/// Keeps the visitor trait closed to this crate.
pub trait Sealed {}

/// Sums the encoded length of every field.
pub(super) struct LengthCounter {
    /// Fixed sizes as declared.
    layout: Layout,
    /// Fields seen so far.
    index: usize,
    /// Bytes counted so far.
    total: usize,
}

impl LengthCounter {
    /// Counter at the first field.
    pub(super) const fn new(layout: Layout) -> Self {
        Self {
            layout,
            index: 0,
            total: 0,
        }
    }

    /// The encoded length of the whole container.
    pub(super) const fn total(&self) -> usize {
        self.total
    }
}

impl Sealed for LengthCounter {}

impl FieldVisitor for LengthCounter {
    fn field<T: Ssz>(&mut self, value: &T) {
        self.layout.check::<T>(self.index);
        // A variable field costs its offset plus its body.
        self.total += match T::FIXED_SIZE {
            Some(size) => size,
            None => BYTES_PER_LENGTH_OFFSET + value.encoded_len(),
        };
        self.index += 1;
    }
}

/// Writes the fixed part: fixed fields inline, offsets for variable fields.
pub(super) struct FixedPartWriter<'a> {
    /// The output buffer.
    out: &'a mut Vec<u8>,
    /// Fixed sizes as declared.
    layout: Layout,
    /// Fields seen so far.
    index: usize,
    /// Offset the next variable field's body will start at.
    next_offset: usize,
}

impl<'a> FixedPartWriter<'a> {
    /// Writer whose first variable body starts right after the fixed part.
    pub(super) const fn new(out: &'a mut Vec<u8>, layout: Layout) -> Self {
        Self {
            out,
            layout,
            index: 0,
            next_offset: layout.fixed_part_len(),
        }
    }
}

impl Sealed for FixedPartWriter<'_> {}

impl FieldVisitor for FixedPartWriter<'_> {
    fn field<T: Ssz>(&mut self, value: &T) {
        self.layout.check::<T>(self.index);
        if T::FIXED_SIZE.is_some() {
            value.encode_to(self.out);
        } else {
            // Offsets count from the container's start, so they advance by each body's length.
            self.out
                .extend_from_slice(&Offset::encode(self.next_offset));
            self.next_offset += value.encoded_len();
        }
        self.index += 1;
    }
}

/// Writes the bodies of variable fields, skipping fixed ones.
pub(super) struct VariablePartWriter<'a> {
    /// The output buffer.
    out: &'a mut Vec<u8>,
}

impl<'a> VariablePartWriter<'a> {
    /// Writer appending to the buffer.
    pub(super) const fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }
}

impl Sealed for VariablePartWriter<'_> {}

impl FieldVisitor for VariablePartWriter<'_> {
    fn field<T: Ssz>(&mut self, value: &T) {
        if T::FIXED_SIZE.is_none() {
            value.encode_to(self.out);
        }
    }
}

/// Merkleizes field roots as they are visited.
pub(super) struct RootMerkleizer {
    /// Fixed sizes as declared.
    layout: Layout,
    /// Fields seen so far.
    index: usize,
    /// The tree over the field roots.
    tree: FieldTree,
}

impl RootMerkleizer {
    /// Merkleizer feeding each declared field into the container's tree.
    pub(super) const fn new(layout: Layout, tree: FieldTree) -> Self {
        Self {
            layout,
            index: 0,
            tree,
        }
    }

    /// The container's root.
    pub(super) fn finish(self) -> Root {
        debug_assert_eq!(self.index, self.layout.len(), "container skipped a field");
        self.tree.finish()
    }
}

impl Sealed for RootMerkleizer {}

impl FieldVisitor for RootMerkleizer {
    fn field<T: Ssz>(&mut self, value: &T) {
        self.layout.check::<T>(self.index);
        self.tree.push(value.hash_tree_root());
        self.index += 1;
    }
}

/// Collects field roots, the leaves a proof is built over.
pub(super) struct FieldRoots {
    /// Roots so far, in field order.
    roots: Vec<Root>,
}

impl FieldRoots {
    /// Collector sized for the given number of fields.
    pub(super) fn new(count: usize) -> Self {
        Self {
            roots: Vec::with_capacity(count),
        }
    }

    /// The collected roots.
    pub(super) fn into_roots(self) -> Vec<Root> {
        self.roots
    }
}

impl Sealed for FieldRoots {}

impl FieldVisitor for FieldRoots {
    fn field<T: Ssz>(&mut self, value: &T) {
        self.roots.push(value.hash_tree_root());
    }
}

/// Proves a node inside one chosen field.
pub(super) struct FieldProver {
    /// Position of the chosen field.
    target: usize,
    /// Index of the node within the field's own tree.
    inner: GeneralizedIndex,
    /// Fields seen so far.
    index: usize,
    /// The node and its proof within the field, once found.
    result: Option<(Root, MerkleProof)>,
}

impl FieldProver {
    /// A prover for a node of one field.
    pub(super) const fn new(target: usize, inner: GeneralizedIndex) -> Self {
        Self {
            target,
            inner,
            index: 0,
            result: None,
        }
    }

    /// The node and its proof within the field, when the field could prove it.
    pub(super) fn into_result(self) -> Option<(Root, MerkleProof)> {
        self.result
    }
}

impl Sealed for FieldProver {}

impl FieldVisitor for FieldProver {
    fn field<T: Ssz>(&mut self, value: &T) {
        if self.index == self.target {
            self.result = value.prove(self.inner);
        }
        self.index += 1;
    }
}
