//! Fixed-length collections with structural sharing and a cached hash tree.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Deref, Index, IndexMut},
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

/// A sequence of exactly `N` elements, the spec's `Vector[T, N]`, cheap to clone and re-hash.
///
/// It encodes and hashes exactly like a plain vector.
/// A clone shares every element, and an edit copies only the pack it touches.
/// The root re-hashes only the packs edited since the last root.
pub struct PersistentVector<T, N> {
    /// The elements, always exactly `N` of them.
    elements: Sequence<T>,
    /// The length, carried in the type.
    length: PhantomData<N>,
}

impl<T: Ssz, N: Length> PersistentVector<T, N> {
    /// Vector whose element at each index is computed from that index.
    pub fn from_fn(f: impl FnMut(usize) -> T) -> Self {
        Self::from_sequence(Sequence::from_vec(
            Self::layout(),
            (0..N::LEN).map(f).collect(),
        ))
    }

    /// Vector with every element set to the same value.
    ///
    /// Its full packs are one shared pack, hashed once.
    #[must_use]
    pub fn repeat(value: &T) -> Self
    where
        T: Clone,
    {
        Self::from_sequence(Sequence::repeat(Self::layout(), value, N::LEN))
    }

    /// The pack layout of a tree sized for the length.
    fn layout() -> Layout {
        Layout::binary::<T>(Elements::<T>::depth(N::LEN))
    }
}

impl<T, N> PersistentVector<T, N> {
    /// A vector over a sequence the caller checked against the length.
    const fn from_sequence(elements: Sequence<T>) -> Self {
        Self {
            elements,
            length: PhantomData,
        }
    }
}

impl<T: Clone, N: Length> PersistentVector<T, N> {
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

impl<T: Ssz, N: Length> TryFrom<Vec<T>> for PersistentVector<T, N> {
    type Error = CapacityError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.len() == N::LEN {
            Ok(Self::from_sequence(Sequence::from_vec(
                Self::layout(),
                items,
            )))
        } else {
            Err(CapacityError::WrongLength {
                expected: N::LEN,
                length: items.len(),
            })
        }
    }
}

impl<T: Ssz + Clone + Default, N: Length> Default for PersistentVector<T, N> {
    /// Vector of default elements, whose full packs share one pack.
    fn default() -> Self {
        Self::repeat(&T::default())
    }
}

impl<T, N> Deref for PersistentVector<T, N> {
    type Target = Sequence<T>;

    fn deref(&self) -> &Sequence<T> {
        &self.elements
    }
}

impl<T, N> Index<usize> for PersistentVector<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        &self.elements[index]
    }
}

impl<T: Clone, N: Length> IndexMut<usize> for PersistentVector<T, N> {
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

impl<'a, T, N> IntoIterator for &'a PersistentVector<T, N> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl<'a, T: Clone, N: Length> IntoIterator for &'a mut PersistentVector<T, N> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T, N> Clone for PersistentVector<T, N> {
    /// Shares every element, so a clone costs one reference count.
    fn clone(&self) -> Self {
        Self::from_sequence(self.elements.clone())
    }
}

impl<T: fmt::Debug, N> fmt::Debug for PersistentVector<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.elements, f)
    }
}

impl<T: PartialEq, N> PartialEq for PersistentVector<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.elements == other.elements
    }
}

impl<T: Eq, N> Eq for PersistentVector<T, N> {}

impl<T: Hash, N> Hash for PersistentVector<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.elements.hash(state);
    }
}

impl<T: Ssz + Sync, N: Length> Ssz for PersistentVector<T, N> {
    const FIXED_SIZE: Option<usize> = match T::FIXED_SIZE {
        Some(size) => Some(size * N::LEN),
        None => None,
    };

    fn encoded_len(&self) -> usize {
        self.elements.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.elements.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Invariant: the spec forbids zero-length vectors, and every vector type here is nonempty.
        const { assert!(N::LEN > 0, "an SSZ vector has at least one element") };

        if let Some(size) = Self::FIXED_SIZE
            && bytes.len() != size
        {
            return Err(DecodeError::InvalidLength {
                expected: size,
                actual: bytes.len(),
            });
        }

        let items = Elements::decode(bytes, N::LEN)?;
        if items.len() != N::LEN {
            return Err(DecodeError::InvalidLength {
                expected: N::LEN,
                actual: items.len(),
            });
        }
        Ok(Self::from_sequence(Sequence::from_vec(
            Self::layout(),
            items,
        )))
    }

    fn hash_tree_root(&self) -> Root {
        self.elements.root()
    }

    fn prove(&self, index: GeneralizedIndex) -> Option<(Root, MerkleProof)> {
        self.elements.prove(N::LEN, index)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, Vector};

    #[test]
    fn repeated_vector_matches_the_plain_root() {
        // 8192 roots fill 128 packs of 64, every one the same shared pack.
        let persistent = PersistentVector::<Root, Const<8192>>::repeat(&Root([7; 32]));
        let plain = Vector::<Root, Const<8192>>::repeat(Root([7; 32]));

        assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root());
    }

    #[test]
    fn wrong_length_is_rejected_on_construction() {
        assert_eq!(
            PersistentVector::<u64, Const<4>>::try_from(vec![1, 2, 3]),
            Err(CapacityError::WrongLength {
                expected: 4,
                length: 3
            })
        );
    }

    #[test]
    fn fixed_vector_rejects_short_input() {
        // Four u64 need 32 bytes, and 24 bytes hold only three.
        assert_eq!(
            PersistentVector::<u64, Const<4>>::decode(&[0; 24]),
            Err(DecodeError::InvalidLength {
                expected: 32,
                actual: 24
            })
        );
    }

    proptest! {
        #[test]
        fn edited_ring_buffer_agrees_with_a_plain_vector(
            edits in proptest::collection::vec((any::<usize>(), any::<u64>(), any::<bool>()), 0..60),
        ) {
            // Fixture state: a ring of 1000 u64, three packs of 256 and one partial pack.
            let mut persistent = PersistentVector::<u64, Const<1000>>::from_fn(|index| index as u64);
            let mut plain = Vector::<u64, Const<1000>>::from_fn(|index| index as u64);
            let mut snapshots = Vec::new();

            for (index, value, snapshot) in edits {
                persistent[index % 1000] = value;
                plain[index % 1000] = value;
                if snapshot {
                    // Taking the root warms the caches the next edits must clear.
                    prop_assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root());
                    snapshots.push((persistent.clone(), plain.clone()));
                }
            }

            snapshots.push((persistent, plain));
            for (persistent, plain) in snapshots {
                prop_assert_eq!(persistent.hash_tree_root(), plain.hash_tree_root());
                prop_assert_eq!(persistent.encode(), plain.encode());
                prop_assert_eq!(PersistentVector::decode(&plain.encode()), Ok(persistent));
            }
        }

        #[test]
        fn every_proven_node_matches_a_plain_vector(raw in 1_u64..1024) {
            // A vector of 300 roots has a depth-9 tree, so indices below 1024 reach its leaves.
            let items: Vec<Root> = (0..300_u64)
                .map(|seed| Root::from_partial(&seed.to_le_bytes()))
                .collect();
            let persistent = PersistentVector::<Root, Const<300>>::try_from(items.clone()).unwrap();
            let plain = Vector::<Root, Const<300>>::try_from(items).unwrap();

            let index = GeneralizedIndex::new(raw);
            prop_assert_eq!(persistent.prove(index), plain.prove(index));
        }
    }
}
