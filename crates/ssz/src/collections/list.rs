//! Bounded homogeneous collections.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Deref, DerefMut, RangeBounds},
    vec,
};

use super::elements::Elements;
use crate::{CapacityError, DecodeError, Length, Root, Ssz};

/// A sequence of at most `N` elements, the spec's `List[T, N]`.
///
/// It dereferences to a slice, so elements can be read and overwritten in place.
/// Growing goes through methods that enforce the limit.
pub struct List<T, N> {
    /// The elements, never more than `N` of them.
    items: Vec<T>,
    /// The limit, carried in the type.
    limit: PhantomData<N>,
}

impl<T, N: Length> List<T, N> {
    /// The maximum number of elements.
    pub const LIMIT: usize = N::LEN;

    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            limit: PhantomData,
        }
    }

    /// Appends an element.
    ///
    /// # Errors
    ///
    /// Fails when the list is already at its limit, and leaves it unchanged.
    pub fn push(&mut self, item: T) -> Result<(), CapacityError> {
        if self.items.len() >= N::LEN {
            return Err(CapacityError::ExceedsLimit {
                limit: N::LEN,
                length: self.items.len() + 1,
            });
        }
        self.items.push(item);
        Ok(())
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

    /// A list of the same limit holding each element transformed.
    ///
    /// The length is unchanged, so the result always fits.
    #[must_use]
    pub fn map<U>(&self, transform: impl FnMut(&T) -> U) -> List<U, N> {
        List {
            items: self.items.iter().map(transform).collect(),
            limit: PhantomData,
        }
    }
}

impl<T, N: Length> TryFrom<Vec<T>> for List<T, N> {
    type Error = CapacityError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.len() <= N::LEN {
            Ok(Self {
                items,
                limit: PhantomData,
            })
        } else {
            Err(CapacityError::ExceedsLimit {
                limit: N::LEN,
                length: items.len(),
            })
        }
    }
}

impl<T, N: Length> Default for List<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, N> Deref for List<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.items
    }
}

impl<T, N> DerefMut for List<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

impl<'a, T, N> IntoIterator for &'a List<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<T, N> IntoIterator for List<T, N> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<T: Clone, N> Clone for List<T, N> {
    fn clone(&self) -> Self {
        Self {
            items: self.items.clone(),
            limit: PhantomData,
        }
    }
}

impl<T: fmt::Debug, N> fmt::Debug for List<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.items).finish()
    }
}

impl<T: PartialEq, N> PartialEq for List<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
    }
}

impl<T: Eq, N> Eq for List<T, N> {}

impl<T: Hash, N> Hash for List<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.items.hash(state);
    }
}

impl<T: Ssz, N: Length> Ssz for List<T, N> {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        Elements::encoded_len(&self.items)
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        Elements::encode_to(&self.items, out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            items: Elements::decode(bytes, N::LEN)?,
            limit: PhantomData,
        })
    }

    fn hash_tree_root(&self) -> Root {
        Elements::root(&self.items, N::LEN).mix_in_length(self.items.len())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, Merkleizer};

    type Small = List<u64, Const<4>>;

    #[test]
    fn push_past_the_limit_fails_and_keeps_the_list() {
        // Fixture state: a full list of 4 elements.
        let mut list = Small::try_from(vec![1, 2, 3, 4]).unwrap();

        assert_eq!(
            list.push(5),
            Err(CapacityError::ExceedsLimit {
                limit: 4,
                length: 5
            })
        );
        assert_eq!(list.as_slice(), [1, 2, 3, 4]);
    }

    #[test]
    fn map_keeps_length_and_order() {
        // Fixture state: three elements, each doubled into a list of the same limit.
        let list = Small::try_from(vec![1, 2, 3]).unwrap();

        let doubled: List<u64, Const<4>> = list.map(|item| item * 2);

        assert_eq!(doubled.as_slice(), [2, 4, 6]);
    }

    #[test]
    fn decoding_more_than_the_limit_fails() {
        // Five u64 are 40 bytes, one element over the limit of 4.
        assert_eq!(
            Small::decode(&[0; 40]),
            Err(DecodeError::TooManyElements {
                limit: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn empty_list_root_mixes_zero_length_into_the_zero_tree() {
        // A limit of 4 u64 is one chunk, so the empty tree is the zero chunk.
        assert_eq!(Small::new().hash_tree_root(), Root::ZERO.mix_in_length(0));
    }

    #[test]
    fn root_uses_the_limit_not_the_length() {
        // Fixture state: 2 elements under a limit of 64, so 16 chunks of depth 4.
        let list = List::<u64, Const<64>>::try_from(vec![5, 6]).unwrap();

        let mut contents = Vec::new();
        contents.extend_from_slice(&5_u64.to_le_bytes());
        contents.extend_from_slice(&6_u64.to_le_bytes());
        let expected = Merkleizer::root_of_bytes(&contents, 64 * 8).mix_in_length(2);

        assert_eq!(list.hash_tree_root(), expected);
    }

    #[test]
    fn misaligned_offset_table_is_rejected() {
        // A first offset of 5 would leave a partial offset in the table.
        let bytes = [5, 0, 0, 0, 0, 1];

        assert_eq!(
            List::<List<u8, Const<4>>, Const<4>>::decode(&bytes),
            Err(DecodeError::MisalignedOffsetTable(5))
        );
    }

    #[test]
    fn decreasing_offsets_are_rejected() {
        // Mutation: the second offset points before the first body.
        //
        //     offsets: 8, 7    -> second body would start before the first ends
        let bytes = [8, 0, 0, 0, 7, 0, 0, 0, 1, 2];

        assert_eq!(
            List::<List<u8, Const<4>>, Const<4>>::decode(&bytes),
            Err(DecodeError::OffsetsNotIncreasing {
                previous: 8,
                next: 7
            })
        );
    }

    #[test]
    fn offset_past_the_end_is_rejected() {
        // The first offset claims an 12-byte table, but the input is 8 bytes long.
        let bytes = [12, 0, 0, 0, 12, 0, 0, 0];

        assert_eq!(
            List::<List<u8, Const<4>>, Const<4>>::decode(&bytes),
            Err(DecodeError::OffsetOutOfBounds {
                offset: 12,
                length: 8
            })
        );
    }

    proptest! {
        #[test]
        fn nested_list_round_trips(
            values in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..8), 0..8)
        ) {
            let inner: Vec<List<u8, Const<8>>> =
                values.into_iter().map(|v| List::try_from(v).unwrap()).collect();
            let list = List::<List<u8, Const<8>>, Const<8>>::try_from(inner).unwrap();

            prop_assert_eq!(List::decode(&list.encode()), Ok(list));
        }

        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = List::<List<u16, Const<4>>, Const<8>>::decode(&bytes);
        }

        #[test]
        fn accepted_bytes_re_encode_identically(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            // Strict decoding means an accepted input is the one canonical encoding.
            if let Ok(list) = List::<List<u16, Const<4>>, Const<8>>::decode(&bytes) {
                prop_assert_eq!(list.encode(), bytes);
            }
        }
    }
}
