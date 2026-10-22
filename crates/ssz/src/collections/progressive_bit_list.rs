//! Unbounded bitfields with a progressive hash tree.

use std::fmt;

use crate::{BitList, Const, DecodeError, ProgressiveMerkleizer, Root, Ssz};

/// The bits behind a progressive bitlist: a bitlist whose limit no length reaches.
type Bits = BitList<Const<{ usize::MAX }>>;

/// Any number of bits, the spec's `ProgressiveBitlist`.
///
/// It encodes exactly like a bounded bitlist, with a sentinel bit after the last real bit.
/// Its hash tree grows with the length instead of being sized for a limit, see EIP-7916.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct ProgressiveBitList(Bits);

impl ProgressiveBitList {
    /// A bitlist of the given length with every bit clear.
    #[must_use]
    pub fn with_len(len: usize) -> Self {
        // The limit is the largest length a slice can have, so any length fits.
        Self(Bits::with_len(len).unwrap_or_default())
    }

    /// Number of bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the bitlist has no bits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The bit at an index, or nothing when the index is out of range.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<bool> {
        self.0.get(index)
    }

    /// Sets the bit at an index.
    ///
    /// # Panics
    ///
    /// Panics when the index is out of range.
    pub fn set(&mut self, index: usize, value: bool) {
        self.0.set(index, value);
    }

    /// Iterates over the bits in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = bool> + '_ {
        self.0.iter()
    }

    /// Number of set bits.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.0.count_ones()
    }

    /// Whether every bit set here is also set in the other bitlist.
    ///
    /// Two bitlists of different lengths are never subsets of each other.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.is_subset_of(&other.0)
    }

    /// Whether the two bitlists share a set bit.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.0.intersects(&other.0)
    }

    /// The bitwise union of two bitlists of equal length.
    ///
    /// Returns nothing when the lengths differ.
    #[must_use]
    pub fn union(&self, other: &Self) -> Option<Self> {
        self.0.union(&other.0).map(Self)
    }
}

impl fmt::Debug for ProgressiveBitList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProgressiveBitList(")?;
        for bit in self.iter() {
            f.write_str(if bit { "1" } else { "0" })?;
        }
        f.write_str(")")
    }
}

impl Ssz for ProgressiveBitList {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Bits::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        let mut merkleizer = ProgressiveMerkleizer::new();
        merkleizer.push_bytes(self.0.as_bytes());
        merkleizer.finish().mix_in_length(self.len())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn encoding_keeps_the_sentinel() {
        // Fixture state: bits 1 0 1, so the sentinel lands on bit 3.
        let mut bits = ProgressiveBitList::with_len(3);
        bits.set(0, true);
        bits.set(2, true);

        assert_eq!(bits.encode(), [0b0000_1101]);
    }

    #[test]
    fn root_packs_bits_into_progressive_chunks() {
        // Three bits fit one chunk: 0b101 in its first byte, the rest zero.
        let mut bits = ProgressiveBitList::with_len(3);
        bits.set(0, true);
        bits.set(2, true);

        let mut chunk = [0; 32];
        chunk[0] = 0b101;
        let expected = Root::hash_pair(&Root(chunk), &Root::ZERO).mix_in_length(3);

        assert_eq!(bits.hash_tree_root(), expected);
    }

    #[test]
    fn missing_sentinel_is_rejected() {
        assert_eq!(
            ProgressiveBitList::decode(&[1, 0]),
            Err(DecodeError::MissingSentinel { length: 2 })
        );
    }

    proptest! {
        #[test]
        fn round_trips(bits in proptest::collection::vec(any::<bool>(), 0..=300)) {
            let mut list = ProgressiveBitList::with_len(bits.len());
            for (index, bit) in bits.iter().enumerate() {
                list.set(index, *bit);
            }

            prop_assert_eq!(ProgressiveBitList::decode(&list.encode()), Ok(list));
        }
    }
}
