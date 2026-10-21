//! The visitors that turn a field walk into each SSZ operation.

use crate::{BYTES_PER_LENGTH_OFFSET, FieldVisitor, Merkleizer, Root, Ssz, offset::Offset};

/// Keeps the visitor trait closed to this crate.
pub trait Sealed {}

/// Checks a visited field against the declared sizes, in debug builds.
fn check_declared<T: Ssz>(fields: &[Option<usize>], index: usize) {
    debug_assert!(
        index < fields.len(),
        "container visits more fields than it declares"
    );
    debug_assert_eq!(
        fields[index],
        T::FIXED_SIZE,
        "field {index} does not match its declared size"
    );
}

/// Sums the encoded length of every field.
pub(super) struct LengthCounter {
    /// Fixed sizes as declared.
    fields: &'static [Option<usize>],
    /// Fields seen so far.
    index: usize,
    /// Bytes counted so far.
    total: usize,
}

impl LengthCounter {
    /// Counter at the first field.
    pub(super) const fn new(fields: &'static [Option<usize>]) -> Self {
        Self {
            fields,
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
        check_declared::<T>(self.fields, self.index);
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
    fields: &'static [Option<usize>],
    /// Fields seen so far.
    index: usize,
    /// Offset the next variable field's body will start at.
    next_offset: usize,
}

impl<'a> FixedPartWriter<'a> {
    /// Writer whose first variable body starts right after the fixed part.
    pub(super) const fn new(
        out: &'a mut Vec<u8>,
        fields: &'static [Option<usize>],
        fixed_part_len: usize,
    ) -> Self {
        Self {
            out,
            fields,
            index: 0,
            next_offset: fixed_part_len,
        }
    }
}

impl Sealed for FixedPartWriter<'_> {}

impl FieldVisitor for FixedPartWriter<'_> {
    fn field<T: Ssz>(&mut self, value: &T) {
        check_declared::<T>(self.fields, self.index);
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
    fields: &'static [Option<usize>],
    /// Fields seen so far.
    index: usize,
    /// The tree over the field roots.
    merkleizer: Merkleizer,
}

impl RootMerkleizer {
    /// Merkleizer with one leaf slot per declared field.
    pub(super) fn new(fields: &'static [Option<usize>]) -> Self {
        Self {
            fields,
            index: 0,
            merkleizer: Merkleizer::with_limit(fields.len()),
        }
    }

    /// The container's root.
    pub(super) fn finish(self) -> Root {
        debug_assert_eq!(self.index, self.fields.len(), "container skipped a field");
        self.merkleizer.finish()
    }
}

impl Sealed for RootMerkleizer {}

impl FieldVisitor for RootMerkleizer {
    fn field<T: Ssz>(&mut self, value: &T) {
        check_declared::<T>(self.fields, self.index);
        self.merkleizer.push(value.hash_tree_root());
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
