//! The visitors that turn a look at the held option into each SSZ operation.

use crate::{GeneralizedIndex, MerkleProof, OptionVisitor, Root, Ssz};

/// Keeps the visitor trait closed to this crate.
pub trait Sealed {}

/// Measures the encoded length of the held option.
pub(super) struct OptionLength {
    /// Bytes counted so far.
    total: usize,
}

impl OptionLength {
    /// A counter at zero.
    pub(super) const fn new() -> Self {
        Self { total: 0 }
    }

    /// The encoded length of the option, without the selector.
    pub(super) const fn total(&self) -> usize {
        self.total
    }
}

impl Sealed for OptionLength {}

impl OptionVisitor for OptionLength {
    fn option<T: Ssz>(&mut self, value: &T) {
        self.total += value.encoded_len();
    }
}

/// Appends the encoding of the held option.
pub(super) struct OptionEncoder<'a> {
    /// The output buffer.
    out: &'a mut Vec<u8>,
}

impl<'a> OptionEncoder<'a> {
    /// An encoder appending to the buffer.
    pub(super) const fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }
}

impl Sealed for OptionEncoder<'_> {}

impl OptionVisitor for OptionEncoder<'_> {
    fn option<T: Ssz>(&mut self, value: &T) {
        value.encode_to(self.out);
    }
}

/// Computes the root of the held option.
pub(super) struct OptionRoot {
    /// The root, once the option is visited.
    root: Root,
}

impl OptionRoot {
    /// A visitor that has seen no option yet.
    pub(super) const fn new() -> Self {
        Self { root: Root::ZERO }
    }

    /// The option's root.
    pub(super) const fn into_root(self) -> Root {
        self.root
    }
}

impl Sealed for OptionRoot {}

impl OptionVisitor for OptionRoot {
    fn option<T: Ssz>(&mut self, value: &T) {
        self.root = value.hash_tree_root();
    }
}

/// Proves a node inside the held option.
pub(super) struct OptionProver {
    /// Index of the node within the option's own tree.
    inner: GeneralizedIndex,
    /// The node and its proof within the option, once found.
    result: Option<(Root, MerkleProof)>,
}

impl OptionProver {
    /// A prover for a node of the option.
    pub(super) const fn new(inner: GeneralizedIndex) -> Self {
        Self {
            inner,
            result: None,
        }
    }

    /// The node and its proof within the option, when the option could prove it.
    pub(super) fn into_result(self) -> Option<(Root, MerkleProof)> {
        self.result
    }
}

impl Sealed for OptionProver {}

impl OptionVisitor for OptionProver {
    fn option<T: Ssz>(&mut self, value: &T) {
        self.result = value.prove(self.inner);
    }
}
