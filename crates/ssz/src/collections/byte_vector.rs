//! Fixed-length byte strings too large for the stack.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use crate::{CapacityError, DecodeError, Length, Merkleizer, Root, Ssz};

/// Exactly `N` bytes on the heap, the spec's `ByteVector[N]` for large `N`.
///
/// Small byte vectors are plain arrays.
/// This type holds the large ones, such as a 128 KiB blob, which would overflow a stack.
pub struct ByteVector<N> {
    /// The bytes, always exactly `N` of them.
    bytes: Box<[u8]>,
    /// The length, carried in the type.
    length: PhantomData<N>,
}

impl<N: Length> ByteVector<N> {
    /// The all-zero byte vector.
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            bytes: vec![0; N::LEN].into_boxed_slice(),
            length: PhantomData,
        }
    }
}

impl<N: Length> TryFrom<&[u8]> for ByteVector<N> {
    type Error = CapacityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == N::LEN {
            Ok(Self {
                bytes: bytes.into(),
                length: PhantomData,
            })
        } else {
            Err(CapacityError::WrongLength {
                expected: N::LEN,
                length: bytes.len(),
            })
        }
    }
}

impl<N: Length> Default for ByteVector<N> {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<N> Deref for ByteVector<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<N> DerefMut for ByteVector<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<N> Clone for ByteVector<N> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            length: PhantomData,
        }
    }
}

impl<N> fmt::Debug for ByteVector<N> {
    /// Shows the length and the first bytes, since a blob printed in full is unreadable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteVector[{}](0x", self.bytes.len())?;
        for byte in self.bytes.iter().take(8) {
            write!(f, "{byte:02x}")?;
        }
        if self.bytes.len() > 8 {
            f.write_str("..")?;
        }
        f.write_str(")")
    }
}

impl<N> PartialEq for ByteVector<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<N> Eq for ByteVector<N> {}

impl<N> Hash for ByteVector<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<N: Length> Ssz for ByteVector<N> {
    const FIXED_SIZE: Option<usize> = Some(N::LEN);

    fn encoded_len(&self) -> usize {
        N::LEN
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(bytes).map_err(|_| DecodeError::InvalidLength {
            expected: N::LEN,
            actual: bytes.len(),
        })
    }

    fn hash_tree_root(&self) -> Root {
        Merkleizer::root_of_bytes(&self.bytes, N::LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Const, Vector};

    #[test]
    fn root_matches_a_vector_of_bytes() {
        // A byte vector is a vector of packed bytes, so both views must agree.
        let bytes: Vec<u8> = (0..100).collect();
        let heap = ByteVector::<Const<100>>::try_from(bytes.as_slice()).unwrap();
        let generic = Vector::<u8, Const<100>>::try_from(bytes).unwrap();

        assert_eq!(heap.hash_tree_root(), generic.hash_tree_root());
        assert_eq!(heap.encode(), generic.encode());
    }
}
