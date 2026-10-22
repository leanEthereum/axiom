//! Unbounded byte strings, merkleized progressively.

use std::ops::Deref;

use crate::{DecodeError, Root, Schema, Ssz, collections::Elements};

/// Any number of bytes, the spec's `ProgressiveByteList` of EIP-7916.
///
/// It is a progressive list of packed bytes, written and read as one byte string.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProgressiveByteList(Vec<u8>);

impl ProgressiveByteList {
    /// The bytes as an owned buffer.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for ProgressiveByteList {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for ProgressiveByteList {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Ssz for ProgressiveByteList {
    const SCHEMA: Schema = Schema::ProgressiveByteList;
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        self.0.len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(bytes.to_vec()))
    }

    fn hash_tree_root(&self) -> Root {
        Elements::progressive_root(&self.0).mix_in_length(self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::ProgressiveList;

    proptest! {
        #[test]
        fn matches_a_progressive_list_of_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..=200)) {
            // The byte string encodes and hashes as the progressive list of its bytes.
            let string = ProgressiveByteList::from(bytes.clone());
            let list = ProgressiveList::from(bytes);
            prop_assert_eq!(string.hash_tree_root(), list.hash_tree_root());
            prop_assert_eq!(string.encode(), list.encode());
        }
    }
}
