//! A run of elements that forms one subtree, with that subtree's root cached.

use std::sync::OnceLock;

use crate::{Root, Ssz, collections::Elements};

/// A run of consecutive elements, shared between sequences until one of them edits it.
///
/// # Invariants
///
/// The cached root, when set, is the root of the elements as they are now.
/// Every edit passes through one method, which clears it first.
#[derive(Clone, Debug)]
pub(crate) struct Pack<T> {
    /// The elements, never more than the pack's capacity.
    items: Vec<T>,
    /// Root of the pack's subtree, computed on first use.
    root: OnceLock<Root>,
}

impl<T> Pack<T> {
    /// A pack holding the given elements, with no root yet.
    pub(crate) const fn new(items: Vec<T>) -> Self {
        Self {
            items,
            root: OnceLock::new(),
        }
    }

    /// The elements.
    pub(crate) fn items(&self) -> &[T] {
        &self.items
    }

    /// The elements, for an edit, which drops the cached root.
    pub(crate) fn items_mut(&mut self) -> &mut Vec<T> {
        // Invariant: the root is cleared before any element can change.
        self.root.take();
        &mut self.items
    }

    /// The elements, given up.
    pub(crate) fn into_items(self) -> Vec<T> {
        self.items
    }

    /// Whether the root is already cached.
    pub(crate) fn is_hashed(&self) -> bool {
        self.root.get().is_some()
    }
}

impl<T: Ssz> Pack<T> {
    /// Root of the pack's subtree of the given height, computed once.
    ///
    /// A sequence always asks one pack for the same height, the one its layout fixes.
    pub(crate) fn root(&self, height: usize) -> Root {
        *self
            .root
            .get_or_init(|| Elements::subtree_root(&self.items, height))
    }
}
