//! Unbounded homogeneous collections with a progressive hash tree.

use std::{
    ops::{Deref, DerefMut, RangeBounds},
    vec,
};

use super::elements::Elements;
use crate::{DecodeError, Root, Ssz};

/// A sequence of any length, the spec's `ProgressiveList[T]`.
///
/// It encodes exactly like a bounded list.
/// Its hash tree grows with the length instead of being sized for a limit, see EIP-7916.
///
/// It dereferences to a slice, so elements can be read and overwritten in place.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgressiveList<T> {
    /// The elements.
    items: Vec<T>,
}

impl<T> ProgressiveList<T> {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Appends an element.
    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }

    /// Removes and returns the last element.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }

    /// Keeps only the elements the predicate accepts, preserving order.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.items.retain(keep);
    }

    /// Shortens the list to at most the given length.
    pub fn truncate(&mut self, length: usize) {
        self.items.truncate(length);
    }

    /// Removes every element.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Removes a range of elements and yields them.
    pub fn drain(&mut self, range: impl RangeBounds<usize>) -> vec::Drain<'_, T> {
        self.items.drain(range)
    }

    /// The elements as an owned buffer.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }

    /// The elements as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// A list holding each element transformed.
    #[must_use]
    pub fn map<U>(&self, transform: impl FnMut(&T) -> U) -> ProgressiveList<U> {
        ProgressiveList {
            items: self.items.iter().map(transform).collect(),
        }
    }
}

impl<T> Default for ProgressiveList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for ProgressiveList<T> {
    fn from(items: Vec<T>) -> Self {
        Self { items }
    }
}

impl<T> FromIterator<T> for ProgressiveList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> Self {
        Self {
            items: items.into_iter().collect(),
        }
    }
}

impl<T> Deref for ProgressiveList<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.items
    }
}

impl<T> DerefMut for ProgressiveList<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

impl<'a, T> IntoIterator for &'a ProgressiveList<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<T> IntoIterator for ProgressiveList<T> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<T: Ssz> Ssz for ProgressiveList<T> {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        Elements::encoded_len(&self.items)
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        Elements::encode_to(&self.items, out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        // The input's own length bounds the element count, so no limit applies.
        Ok(Self {
            items: Elements::decode(bytes, usize::MAX)?,
        })
    }

    fn hash_tree_root(&self) -> Root {
        Elements::progressive_root(&self.items).mix_in_length(self.items.len())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, List, ProgressiveMerkleizer};

    #[test]
    fn empty_list_root_mixes_zero_length_into_the_zero_chunk() {
        assert_eq!(
            ProgressiveList::<u64>::new().hash_tree_root(),
            Root::ZERO.mix_in_length(0)
        );
    }

    #[test]
    fn basic_elements_pack_into_progressive_chunks() {
        // Five u64 are 40 bytes: one full chunk and one chunk of 8 bytes.
        let list = ProgressiveList::from(vec![1_u64, 2, 3, 4, 5]);

        let mut packed = Vec::new();
        for value in 1_u64..=5 {
            packed.extend_from_slice(&value.to_le_bytes());
        }
        let mut merkleizer = ProgressiveMerkleizer::new();
        merkleizer.push_bytes(&packed);

        assert_eq!(list.hash_tree_root(), merkleizer.finish().mix_in_length(5));
    }

    #[test]
    fn composite_elements_contribute_one_root_each() {
        // Two inner lists: their roots are the two leaves of the progressive tree.
        let inner = [
            List::<u8, Const<4>>::try_from(vec![1]).unwrap(),
            List::<u8, Const<4>>::try_from(vec![2, 3]).unwrap(),
        ];
        let list = ProgressiveList::from(inner.to_vec());

        let mut merkleizer = ProgressiveMerkleizer::new();
        merkleizer.push(inner[0].hash_tree_root());
        merkleizer.push(inner[1].hash_tree_root());

        assert_eq!(list.hash_tree_root(), merkleizer.finish().mix_in_length(2));
    }

    proptest! {
        #[test]
        fn encoding_equals_a_bounded_list(values in proptest::collection::vec(any::<u16>(), 0..64)) {
            let progressive = ProgressiveList::from(values.clone());
            let bounded = List::<u16, Const<64>>::try_from(values).unwrap();

            prop_assert_eq!(progressive.encode(), bounded.encode());
        }

        #[test]
        fn nested_list_round_trips(
            values in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 0..8)
        ) {
            let list: ProgressiveList<ProgressiveList<u8>> =
                values.into_iter().map(ProgressiveList::from).collect();

            prop_assert_eq!(ProgressiveList::decode(&list.encode()), Ok(list));
        }
    }
}
