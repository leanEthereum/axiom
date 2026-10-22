//! Bounded collections with structural sharing and a cached hash tree.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Deref, Index, IndexMut, RangeBounds},
    vec,
};

use super::{
    iter::{Iter, IterMut},
    layout::Layout,
    sequence::Sequence,
    sequence_mut::SequenceMut,
};
use crate::{
    CapacityError, DecodeError, GeneralizedIndex, Length, MerkleProof, Root, Ssz,
    collections::Elements,
};

/// A sequence of at most `N` elements, the spec's `List[T, N]`, cheap to clone and re-hash.
///
/// It encodes and hashes exactly like a plain list.
/// A clone shares every element, and an edit copies only the pack it touches.
/// The root re-hashes only the packs edited since the last root.
pub struct PersistentList<T, N> {
    /// The elements, never more than `N` of them.
    elements: Sequence<T>,
    /// The limit, carried in the type.
    limit: PhantomData<N>,
}

impl<T: Ssz, N: Length> PersistentList<T, N> {
    /// The maximum number of elements.
    pub const LIMIT: usize = N::LEN;

    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::from_sequence(Sequence::empty(Self::layout()))
    }

    /// A list of the same limit holding each element transformed.
    ///
    /// The length is unchanged, so the result always fits.
    #[must_use]
    pub fn map<U: Ssz>(&self, transform: impl FnMut(&T) -> U) -> PersistentList<U, N> {
        PersistentList::from_sequence(Sequence::from_vec(
            PersistentList::<U, N>::layout(),
            self.elements.iter().map(transform).collect(),
        ))
    }

    /// The pack layout of a tree sized for the limit.
    fn layout() -> Layout {
        Layout::binary::<T>(Elements::<T>::depth(N::LEN))
    }
}

impl<T, N> PersistentList<T, N> {
    /// A list over a sequence the caller checked against the limit.
    const fn from_sequence(elements: Sequence<T>) -> Self {
        Self {
            elements,
            limit: PhantomData,
        }
    }
}

impl<T: Clone, N: Length> PersistentList<T, N> {
    /// Appends an element.
    ///
    /// # Errors
    ///
    /// Fails when the list is already at its limit, and leaves it unchanged.
    pub fn push(&mut self, item: T) -> Result<(), CapacityError> {
        if self.elements.len() >= N::LEN {
            return Err(CapacityError::ExceedsLimit {
                limit: N::LEN,
                length: self.elements.len() + 1,
            });
        }
        self.elements.push(item);
        Ok(())
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

impl<T: Ssz, N: Length> TryFrom<Vec<T>> for PersistentList<T, N> {
    type Error = CapacityError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.len() <= N::LEN {
            Ok(Self::from_sequence(Sequence::from_vec(
                Self::layout(),
                items,
            )))
        } else {
            Err(CapacityError::ExceedsLimit {
                limit: N::LEN,
                length: items.len(),
            })
        }
    }
}

impl<T: Ssz, N: Length> Default for PersistentList<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, N> Deref for PersistentList<T, N> {
    type Target = Sequence<T>;

    fn deref(&self) -> &Sequence<T> {
        &self.elements
    }
}

impl<T, N> Index<usize> for PersistentList<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        &self.elements[index]
    }
}

impl<T: Clone, N: Length> IndexMut<usize> for PersistentList<T, N> {
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

impl<'a, T, N> IntoIterator for &'a PersistentList<T, N> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl<'a, T: Clone, N: Length> IntoIterator for &'a mut PersistentList<T, N> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T, N> Clone for PersistentList<T, N> {
    /// Shares every element, so a clone costs one reference count.
    fn clone(&self) -> Self {
        Self {
            elements: self.elements.clone(),
            limit: PhantomData,
        }
    }
}

impl<T: fmt::Debug, N> fmt::Debug for PersistentList<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.elements, f)
    }
}

impl<T: PartialEq, N> PartialEq for PersistentList<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.elements == other.elements
    }
}

impl<T: Eq, N> Eq for PersistentList<T, N> {}

impl<T: Hash, N> Hash for PersistentList<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.elements.hash(state);
    }
}

impl<T: Ssz + Sync, N: Length> Ssz for PersistentList<T, N> {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        self.elements.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.elements.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_sequence(Sequence::from_vec(
            Self::layout(),
            Elements::decode(bytes, N::LEN)?,
        )))
    }

    fn hash_tree_root(&self) -> Root {
        self.elements.root().mix_in_length(self.elements.len())
    }

    /// Proves a node: the length on the right of the root, the elements' tree on the left.
    fn prove(&self, index: GeneralizedIndex) -> Option<(Root, MerkleProof)> {
        let data = self.elements.root();
        let length_chunk = Root::from_partial(&(self.elements.len() as u64).to_le_bytes());
        match index.get() {
            1 => Some((
                Root::hash_pair(&data, &length_chunk),
                MerkleProof::default(),
            )),
            3 => Some((length_chunk, MerkleProof { branch: vec![data] })),
            _ => {
                let inner = index.relative_to(GeneralizedIndex::new(2))?;
                let (leaf, mut proof) = self.elements.prove(N::LEN, inner)?;
                proof.branch.push(length_chunk);
                Some((leaf, proof))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use proptest::prelude::*;

    use super::*;
    use crate::{Const, List};

    /// One edit, applied alike to the persistent list and to a plain list.
    #[derive(Clone, Debug)]
    enum Edit {
        Set(usize, u64),
        Push(u64),
        Pop,
        Truncate(usize),
        Retain(u64),
        DrainFront(usize),
        DrainTail(usize),
        AddToAll(u64),
        Hash,
        Snapshot,
    }

    fn edit() -> impl Strategy<Value = Edit> {
        prop_oneof![
            4 => (any::<usize>(), any::<u64>()).prop_map(|(index, value)| Edit::Set(index, value)),
            3 => any::<u64>().prop_map(Edit::Push),
            1 => Just(Edit::Pop),
            1 => any::<usize>().prop_map(Edit::Truncate),
            1 => (2_u64..5).prop_map(Edit::Retain),
            1 => (0_usize..40).prop_map(Edit::DrainFront),
            1 => (0_usize..40).prop_map(Edit::DrainTail),
            1 => any::<u64>().prop_map(Edit::AddToAll),
            2 => Just(Edit::Hash),
            1 => Just(Edit::Snapshot),
        ]
    }

    /// Element types under test, built from a seed and bumped by an amount.
    trait Sample: Ssz + Clone + PartialEq + Debug + Sync {
        fn sample(seed: u64) -> Self;
        fn bump(&mut self, amount: u64);
        fn key(&self) -> u64;
    }

    impl Sample for u64 {
        fn sample(seed: u64) -> Self {
            seed
        }
        fn bump(&mut self, amount: u64) {
            *self = self.wrapping_add(amount);
        }
        fn key(&self) -> u64 {
            *self
        }
    }

    impl Sample for u8 {
        fn sample(seed: u64) -> Self {
            seed as Self
        }
        fn bump(&mut self, amount: u64) {
            *self = self.wrapping_add(amount as Self);
        }
        fn key(&self) -> u64 {
            u64::from(*self)
        }
    }

    impl Sample for Root {
        fn sample(seed: u64) -> Self {
            Self::from_partial(&seed.to_le_bytes())
        }
        fn bump(&mut self, amount: u64) {
            self.0[31] = self.0[31].wrapping_add(amount as u8 | 1);
        }
        fn key(&self) -> u64 {
            u64::from(self.0[0])
        }
    }

    impl Sample for List<u8, Const<4>> {
        fn sample(seed: u64) -> Self {
            Self::try_from(vec![seed as u8; (seed % 5) as usize]).unwrap()
        }
        fn bump(&mut self, amount: u64) {
            if self.push(amount as u8).is_err() {
                self.clear();
            }
        }
        fn key(&self) -> u64 {
            self.len() as u64
        }
    }

    /// Applies edits to a persistent list and a plain one, checking they agree after each.
    ///
    /// Snapshots taken along the way must keep their contents and roots whatever comes after.
    fn agrees_with_plain_list<T: Sample, N: Length>(edits: &[Edit], initial: usize) {
        let start: Vec<T> = (0..initial as u64).map(T::sample).collect();
        let mut persistent = PersistentList::<T, N>::try_from(start.clone()).unwrap();
        let mut plain = List::<T, N>::try_from(start).unwrap();
        let mut snapshots = Vec::new();

        for edit in edits {
            match edit {
                Edit::Set(index, value) => {
                    if !plain.is_empty() {
                        let index = index % plain.len();
                        persistent[index] = T::sample(*value);
                        plain[index] = T::sample(*value);
                    }
                }
                Edit::Push(value) => {
                    assert_eq!(
                        persistent.push(T::sample(*value)),
                        plain.push(T::sample(*value))
                    );
                }
                Edit::Pop => assert_eq!(persistent.pop(), plain.pop()),
                Edit::Truncate(length) => {
                    let length = length % (plain.len() + 1);
                    persistent.truncate(length);
                    plain.truncate(length);
                }
                Edit::Retain(modulus) => {
                    persistent.retain(|item| item.key() % modulus != 0);
                    plain.retain(|item| item.key() % modulus != 0);
                }
                Edit::DrainFront(count) => {
                    let count = (*count).min(plain.len());
                    assert!(persistent.drain(..count).eq(plain.drain(..count)));
                }
                Edit::DrainTail(count) => {
                    let start = plain.len().saturating_sub(*count);
                    assert!(persistent.drain(start..).eq(plain.drain(start..)));
                }
                Edit::AddToAll(amount) => {
                    persistent.iter_mut().for_each(|item| item.bump(*amount));
                    plain.iter_mut().for_each(|item| item.bump(*amount));
                }
                Edit::Hash => {
                    assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root());
                }
                Edit::Snapshot => snapshots.push((persistent.clone(), plain.clone())),
            }
            assert_eq!(persistent.len(), plain.len());
        }

        // The final value, and every snapshot, matches the plain list in every view.
        snapshots.push((persistent, plain));
        for (persistent, plain) in snapshots {
            assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root());
            assert_eq!(persistent.encode(), plain.encode());
            assert_eq!(persistent.to_vec(), plain.as_slice());
            assert_eq!(
                PersistentList::<T, N>::decode(&plain.encode()),
                Ok(persistent)
            );
        }
    }

    #[test]
    fn push_past_the_limit_fails_and_keeps_the_list() {
        // Fixture state: a full list of 4 elements.
        let mut list = PersistentList::<u64, Const<4>>::try_from(vec![1, 2, 3, 4]).unwrap();

        assert_eq!(
            list.push(5),
            Err(CapacityError::ExceedsLimit {
                limit: 4,
                length: 5
            })
        );
        assert_eq!(list.to_vec(), [1, 2, 3, 4]);
    }

    #[test]
    fn a_proof_reaches_into_a_list_across_packs() {
        // Fixture state: 300 roots under a limit of 1024, so five packs of 64 leaves.
        let list = PersistentList::<Root, Const<1024>>::try_from(
            (0..300_u64).map(Root::sample).collect::<Vec<_>>(),
        )
        .unwrap();
        let plain = List::<Root, Const<1024>>::try_from(list.to_vec()).unwrap();

        // Leaf 200 of the depth-10 data tree, under node 2: index 2^11 + 200.
        let index = GeneralizedIndex::new((1 << 11) + 200);
        assert_eq!(list.prove(index), plain.prove(index));
        let (leaf, proof) = list.prove(index).unwrap();
        assert_eq!(leaf, Root::sample(200));
        assert!(proof.verify(leaf, index, list.hash_tree_root()));
    }

    proptest! {
        #[test]
        fn packed_u64_agrees_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..1100,
        ) {
            agrees_with_plain_list::<u64, Const<4096>>(&edits, initial);
        }

        #[test]
        fn packed_u8_agrees_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..5000,
        ) {
            agrees_with_plain_list::<u8, Const<1_099_511_627_776>>(&edits, initial);
        }

        #[test]
        fn composite_roots_agree_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..300,
        ) {
            agrees_with_plain_list::<Root, Const<1024>>(&edits, initial);
        }

        #[test]
        fn variable_size_elements_agree_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..150,
        ) {
            agrees_with_plain_list::<List<u8, Const<4>>, Const<200>>(&edits, initial);
        }

        #[test]
        fn a_shallow_list_agrees_with_a_plain_list(
            edits in proptest::collection::vec(edit(), 0..40),
            initial in 0_usize..6,
        ) {
            // A limit of 6 roots is a depth-3 tree, shallower than one pack.
            agrees_with_plain_list::<Root, Const<6>>(&edits, initial);
        }
    }
}
