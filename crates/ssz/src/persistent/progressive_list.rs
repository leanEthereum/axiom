//! Unbounded collections with a progressive hash tree, structural sharing, and cached roots.

use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::{Deref, Index, IndexMut, RangeBounds},
    vec,
};

use super::{
    iter::{Iter, IterMut},
    layout::Layout,
    sequence::Sequence,
    sequence_mut::SequenceMut,
};
use crate::{DecodeError, Root, Ssz, collections::Elements};

/// A sequence of any length, the spec's `ProgressiveList[T]`, cheap to clone and re-hash.
///
/// It encodes and hashes exactly like a plain progressive list, see EIP-7916.
/// A clone shares every element, and an edit copies only the pack it touches.
/// The root re-hashes only the packs edited since the last root.
pub struct PersistentProgressiveList<T> {
    /// The elements.
    elements: Sequence<T>,
}

impl<T: Ssz> PersistentProgressiveList<T> {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            elements: Sequence::empty(Layout::progressive::<T>()),
        }
    }

    /// A list holding one value repeated, whose full packs share one pack.
    #[must_use]
    pub fn repeat(value: &T, length: usize) -> Self
    where
        T: Clone,
    {
        Self {
            elements: Sequence::repeat(Layout::progressive::<T>(), value, length),
        }
    }

    /// A list holding each element transformed.
    #[must_use]
    pub fn map<U: Ssz>(&self, transform: impl FnMut(&T) -> U) -> PersistentProgressiveList<U> {
        PersistentProgressiveList {
            elements: Sequence::from_vec(
                Layout::progressive::<U>(),
                self.elements.iter().map(transform).collect(),
            ),
        }
    }
}

impl<T: Clone> PersistentProgressiveList<T> {
    /// Appends an element.
    pub fn push(&mut self, item: T) {
        self.elements.push(item);
    }

    /// Removes and returns the last element.
    pub fn pop(&mut self) -> Option<T> {
        self.elements.pop()
    }

    /// Keeps only the elements the predicate accepts, preserving order.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.elements.retain(keep);
    }

    /// Shortens the list to at most the given length.
    pub fn truncate(&mut self, length: usize) {
        self.elements.truncate(length);
    }

    /// Removes every element.
    pub fn clear(&mut self) {
        self.elements.clear();
    }

    /// Removes a range of elements and yields them.
    ///
    /// # Panics
    ///
    /// Panics when the range is out of bounds or decreasing, as a slice range would.
    pub fn drain(&mut self, range: impl RangeBounds<usize>) -> vec::IntoIter<T> {
        self.elements.drain(range)
    }

    /// The elements as an owned buffer.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.elements.into_vec()
    }

    /// The element at an index, for an edit.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.elements.get_mut(index)
    }

    /// Iterator over the elements for edits, in order.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        self.elements.iter_mut()
    }

    /// The elements as a fixed-length view, for edits in place.
    pub const fn elements_mut(&mut self) -> SequenceMut<'_, T> {
        SequenceMut::new(&mut self.elements)
    }
}

impl<T: Ssz> Default for PersistentProgressiveList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ssz> From<Vec<T>> for PersistentProgressiveList<T> {
    fn from(items: Vec<T>) -> Self {
        Self {
            elements: Sequence::from_vec(Layout::progressive::<T>(), items),
        }
    }
}

impl<T: Ssz> FromIterator<T> for PersistentProgressiveList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> Self {
        Self::from(items.into_iter().collect::<Vec<T>>())
    }
}

impl<T> Deref for PersistentProgressiveList<T> {
    type Target = Sequence<T>;

    fn deref(&self) -> &Sequence<T> {
        &self.elements
    }
}

impl<T> Index<usize> for PersistentProgressiveList<T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        &self.elements[index]
    }
}

impl<T: Clone> IndexMut<usize> for PersistentProgressiveList<T> {
    /// The element at an index, for an edit.
    ///
    /// # Panics
    ///
    /// Panics when the index is out of bounds, as a slice would.
    fn index_mut(&mut self, index: usize) -> &mut T {
        let len = self.elements.len();
        match self.elements.get_mut(index) {
            Some(item) => item,
            None => panic!("index out of bounds: the len is {len} but the index is {index}"),
        }
    }
}

impl<'a, T> IntoIterator for &'a PersistentProgressiveList<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut PersistentProgressiveList<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T> Clone for PersistentProgressiveList<T> {
    /// Shares every element, so a clone costs one reference count.
    fn clone(&self) -> Self {
        Self {
            elements: self.elements.clone(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for PersistentProgressiveList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.elements, f)
    }
}

impl<T: PartialEq> PartialEq for PersistentProgressiveList<T> {
    fn eq(&self, other: &Self) -> bool {
        self.elements == other.elements
    }
}

impl<T: Eq> Eq for PersistentProgressiveList<T> {}

impl<T: Hash> Hash for PersistentProgressiveList<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.elements.hash(state);
    }
}

impl<T: Ssz + Sync> Ssz for PersistentProgressiveList<T> {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        self.elements.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.elements.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        // The input's own length bounds the element count, so no limit applies.
        Ok(Self::from(Elements::decode(bytes, usize::MAX)?))
    }

    fn hash_tree_root(&self) -> Root {
        self.elements.root().mix_in_length(self.elements.len())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, List, ProgressiveList};

    /// One edit: set an element, push, pop, truncate, or take the root to warm the caches.
    #[derive(Clone, Debug)]
    enum Edit {
        Set(usize, u16),
        Push(u16),
        Pop,
        Truncate(usize),
        Hash,
        Snapshot,
    }

    fn edit() -> impl Strategy<Value = Edit> {
        prop_oneof![
            4 => (any::<usize>(), any::<u16>()).prop_map(|(index, value)| Edit::Set(index, value)),
            3 => any::<u16>().prop_map(Edit::Push),
            1 => Just(Edit::Pop),
            1 => any::<usize>().prop_map(Edit::Truncate),
            2 => Just(Edit::Hash),
            1 => Just(Edit::Snapshot),
        ]
    }

    /// Applies edits to a persistent and a plain progressive list, checking they agree.
    fn agrees_with_plain_list<T: Ssz + Clone + PartialEq + fmt::Debug + Sync>(
        edits: &[Edit],
        initial: usize,
        make: impl Fn(u16) -> T,
    ) {
        let start: Vec<T> = (0..initial).map(|seed| make(seed as u16)).collect();
        let mut persistent = PersistentProgressiveList::from(start.clone());
        let mut plain = ProgressiveList::from(start);
        let mut snapshots = Vec::new();

        for edit in edits {
            match edit {
                Edit::Set(index, value) => {
                    if !plain.is_empty() {
                        let index = index % plain.len();
                        persistent[index] = make(*value);
                        plain[index] = make(*value);
                    }
                }
                Edit::Push(value) => {
                    persistent.push(make(*value));
                    plain.push(make(*value));
                }
                Edit::Pop => assert_eq!(persistent.pop(), plain.pop()),
                Edit::Truncate(length) => {
                    let length = length % (plain.len() + 1);
                    persistent.truncate(length);
                    plain.truncate(length);
                }
                Edit::Hash => assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root()),
                Edit::Snapshot => snapshots.push((persistent.clone(), plain.clone())),
            }
        }

        snapshots.push((persistent, plain));
        for (persistent, plain) in snapshots {
            assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root());
            assert_eq!(persistent.encode(), plain.encode());
            assert_eq!(
                PersistentProgressiveList::decode(&plain.encode()),
                Ok(persistent)
            );
        }
    }

    #[test]
    fn empty_list_root_mixes_zero_length_into_the_zero_chunk() {
        assert_eq!(
            PersistentProgressiveList::<u64>::new().hash_tree_root(),
            Root::ZERO.mix_in_length(0)
        );
    }

    #[test]
    fn every_length_through_five_subtrees_matches() {
        // Roots fill subtrees of 1, 4, 16, 64, and 256 leaves: 341 leaves in all.
        // Lengths 0 to 400 cross every subtree boundary, inside the first pack and past it.
        let roots: Vec<Root> = (0..400_u64)
            .map(|seed| Root::from_partial(&seed.to_le_bytes()))
            .collect();
        for length in 0..=400 {
            let items = roots[..length].to_vec();
            assert_eq!(
                PersistentProgressiveList::from(items.clone()).hash_tree_root(),
                ProgressiveList::from(items).hash_tree_root(),
                "length {length}"
            );
        }
    }

    proptest! {
        #[test]
        fn packed_u16_agrees_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..6000,
        ) {
            agrees_with_plain_list(&edits, initial, |value| value);
        }

        #[test]
        fn composite_roots_agree_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..1500,
        ) {
            agrees_with_plain_list(&edits, initial, |value| Root::from_partial(&value.to_le_bytes()));
        }

        #[test]
        fn variable_size_elements_agree_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..120,
        ) {
            agrees_with_plain_list(&edits, initial, |value| {
                List::<u8, Const<4>>::try_from(vec![value as u8; usize::from(value % 5)]).unwrap()
            });
        }
    }
}
