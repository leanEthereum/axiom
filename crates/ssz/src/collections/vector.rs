//! Fixed-length homogeneous collections.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use super::elements::Elements;
use crate::{CapacityError, DecodeError, Length, Root, Ssz};

/// A sequence of exactly `N` elements, the spec's `Vector[T, N]`.
///
/// It dereferences to a slice, so elements can be read and overwritten in place.
/// The length can never change, because a slice cannot grow or shrink.
pub struct Vector<T, N> {
    /// The elements, always exactly `N` of them.
    items: Vec<T>,
    /// The length, carried in the type.
    length: PhantomData<N>,
}

impl<T, N: Length> Vector<T, N> {
    /// Vector whose element at each index is computed from that index.
    pub fn from_fn(f: impl FnMut(usize) -> T) -> Self {
        Self {
            items: (0..N::LEN).map(f).collect(),
            length: PhantomData,
        }
    }

    /// Vector with every element set to the same value.
    #[must_use]
    pub fn repeat(value: T) -> Self
    where
        T: Clone,
    {
        Self {
            items: vec![value; N::LEN],
            length: PhantomData,
        }
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
}

impl<T, N: Length> TryFrom<Vec<T>> for Vector<T, N> {
    type Error = CapacityError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.len() == N::LEN {
            Ok(Self {
                items,
                length: PhantomData,
            })
        } else {
            Err(CapacityError::WrongLength {
                expected: N::LEN,
                length: items.len(),
            })
        }
    }
}

impl<T: Default, N: Length> Default for Vector<T, N> {
    fn default() -> Self {
        Self::from_fn(|_| T::default())
    }
}

impl<T, N> Deref for Vector<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.items
    }
}

impl<T, N> DerefMut for Vector<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

impl<'a, T, N> IntoIterator for &'a Vector<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<T: Clone, N> Clone for Vector<T, N> {
    fn clone(&self) -> Self {
        Self {
            items: self.items.clone(),
            length: PhantomData,
        }
    }
}

impl<T: fmt::Debug, N> fmt::Debug for Vector<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.items).finish()
    }
}

impl<T: PartialEq, N> PartialEq for Vector<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
    }
}

impl<T: Eq, N> Eq for Vector<T, N> {}

impl<T: Hash, N> Hash for Vector<T, N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.items.hash(state);
    }
}

impl<T: Ssz, N: Length> Ssz for Vector<T, N> {
    const FIXED_SIZE: Option<usize> = match T::FIXED_SIZE {
        Some(size) => Some(size * N::LEN),
        None => None,
    };

    fn encoded_len(&self) -> usize {
        Elements::encoded_len(&self.items)
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        Elements::encode_to(&self.items, out);
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
        Ok(Self {
            items,
            length: PhantomData,
        })
    }

    fn hash_tree_root(&self) -> Root {
        Elements::root(&self.items, N::LEN)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, List};

    #[test]
    fn wrong_length_is_rejected_on_construction() {
        assert_eq!(
            Vector::<u64, Const<4>>::try_from(vec![1, 2, 3]),
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
            Vector::<u64, Const<4>>::decode(&[0; 24]),
            Err(DecodeError::InvalidLength {
                expected: 32,
                actual: 24
            })
        );
    }

    #[test]
    fn packed_root_fills_chunks_in_order() {
        // Fixture state: four u64 values pack into exactly one chunk.
        //
        //     chunk = 01..  02..  03..  04..   (8 bytes each, little-endian)
        let vector = Vector::<u64, Const<4>>::try_from(vec![1, 2, 3, 4]).unwrap();

        let mut chunk = [0; 32];
        for (i, value) in [1_u64, 2, 3, 4].iter().enumerate() {
            chunk[i * 8..(i + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(vector.hash_tree_root(), Root(chunk));
    }

    #[test]
    fn variable_vector_round_trips() {
        // Each element is a list, so the vector encodes an offset table first.
        let vector = Vector::<List<u8, Const<4>>, Const<2>>::try_from(vec![
            List::try_from(vec![1, 2]).unwrap(),
            List::try_from(vec![3]).unwrap(),
        ])
        .unwrap();

        //     offsets: 8, 10    bodies: [1, 2] [3]
        assert_eq!(vector.encode(), [8, 0, 0, 0, 10, 0, 0, 0, 1, 2, 3]);
        assert_eq!(Vector::decode(&vector.encode()), Ok(vector));
    }

    proptest! {
        #[test]
        fn u16_vector_round_trips(values in proptest::collection::vec(any::<u16>(), 5)) {
            let vector = Vector::<u16, Const<5>>::try_from(values).unwrap();
            prop_assert_eq!(Vector::decode(&vector.encode()), Ok(vector));
        }
    }
}
