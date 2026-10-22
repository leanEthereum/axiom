//! Bounded byte strings.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
};

use crate::{CapacityError, DecodeError, Length, Merkleizer, Root, Ssz};

/// At most `N` bytes, the spec's `ByteList[N]`.
///
/// It is a list of packed bytes, with a bulk copy in place of a per-byte loop.
pub struct ByteList<N> {
    /// The bytes, never more than `N` of them.
    bytes: Vec<u8>,
    /// The limit, carried in the type.
    limit: PhantomData<N>,
}

impl<N: Length> ByteList<N> {
    /// An empty byte list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            limit: PhantomData,
        }
    }

    /// The bytes as an owned buffer.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl<N: Length> TryFrom<Vec<u8>> for ByteList<N> {
    type Error = CapacityError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() <= N::LEN {
            Ok(Self {
                bytes,
                limit: PhantomData,
            })
        } else {
            Err(CapacityError::ExceedsLimit {
                limit: N::LEN,
                length: bytes.len(),
            })
        }
    }
}

impl<N: Length> TryFrom<&[u8]> for ByteList<N> {
    type Error = CapacityError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.to_vec())
    }
}

impl<N: Length> Default for ByteList<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N> Deref for ByteList<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<N> Clone for ByteList<N> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            limit: PhantomData,
        }
    }
}

impl<N> fmt::Debug for ByteList<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<N> PartialEq for ByteList<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<N> Eq for ByteList<N> {}

impl<N> Hash for ByteList<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<N: Length> Ssz for ByteList<N> {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(bytes).map_err(|_| DecodeError::TooManyElements {
            limit: N::LEN,
            actual: bytes.len(),
        })
    }

    fn hash_tree_root(&self) -> Root {
        Merkleizer::root_of_bytes(&self.bytes, N::LEN).mix_in_length(self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Const, List};

    proptest! {
        #[test]
        fn matches_a_list_of_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..=96)) {
            // The bulk path must equal the generic packed-list path byte for byte.
            let fast = ByteList::<Const<96>>::try_from(bytes.clone()).unwrap();
            let generic = List::<u8, Const<96>>::try_from(bytes).unwrap();

            prop_assert_eq!(fast.hash_tree_root(), generic.hash_tree_root());
            prop_assert_eq!(fast.encode(), generic.encode());
        }
    }
}
