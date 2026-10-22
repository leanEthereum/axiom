//! Bounded bitfields.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use crate::{CapacityError, DecodeError, Length, Merkleizer, Root, Ssz};

/// At most `N` bits, the spec's `Bitlist[N]`.
///
/// The encoding appends one sentinel bit set to 1 right after the last real bit.
/// The highest set bit of the last byte then tells a decoder the length.
///
/// ```text
/// bits     = 1 1 0         (length 3)
/// encoding = 0b0000_1011   (sentinel at bit 3)
/// ```
pub struct BitList<N> {
    /// Packed bits without the sentinel, with every bit past the length held at zero.
    bytes: Vec<u8>,
    /// Number of bits.
    len: usize,
    /// The limit, carried in the type.
    limit: PhantomData<N>,
}

impl<N: Length> BitList<N> {
    /// A bitlist of the given length with every bit clear.
    ///
    /// # Errors
    ///
    /// Fails when the length exceeds the limit.
    pub fn with_len(len: usize) -> Result<Self, CapacityError> {
        if len > N::LEN {
            return Err(CapacityError::ExceedsLimit {
                limit: N::LEN,
                length: len,
            });
        }
        Ok(Self {
            bytes: vec![0; len.div_ceil(8)],
            len,
            limit: PhantomData,
        })
    }

    /// Number of bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the bitlist has no bits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bit at an index, or nothing when the index is out of range.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<bool> {
        (index < self.len).then(|| self.bytes[index / 8] >> (index % 8) & 1 == 1)
    }

    /// Sets the bit at an index.
    ///
    /// # Panics
    ///
    /// Panics when the index is out of range.
    pub fn set(&mut self, index: usize, value: bool) {
        assert!(
            index < self.len,
            "bit index {index} out of range for length {}",
            self.len
        );
        let mask = 1 << (index % 8);
        if value {
            self.bytes[index / 8] |= mask;
        } else {
            self.bytes[index / 8] &= !mask;
        }
    }

    /// Iterates over the bits in order.
    pub fn iter(&self) -> impl Iterator<Item = bool> + '_ {
        (0..self.len).map(|index| self.bytes[index / 8] >> (index % 8) & 1 == 1)
    }

    /// Number of set bits.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.bytes
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Whether every bit set here is also set in the other bitlist.
    ///
    /// Two bitlists of different lengths are never subsets of each other.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .bytes
                .iter()
                .zip(&other.bytes)
                .all(|(mine, theirs)| mine & !theirs == 0)
    }

    /// Whether the two bitlists share a set bit.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.bytes
            .iter()
            .zip(&other.bytes)
            .any(|(mine, theirs)| mine & theirs != 0)
    }

    /// The bitwise union of two bitlists of equal length.
    ///
    /// Returns nothing when the lengths differ.
    #[must_use]
    pub fn union(&self, other: &Self) -> Option<Self> {
        (self.len == other.len).then(|| Self {
            bytes: self
                .bytes
                .iter()
                .zip(&other.bytes)
                .map(|(mine, theirs)| mine | theirs)
                .collect(),
            len: self.len,
            limit: PhantomData,
        })
    }
}

impl<N: Length> Default for BitList<N> {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            len: 0,
            limit: PhantomData,
        }
    }
}

impl<N> Clone for BitList<N> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            len: self.len,
            limit: PhantomData,
        }
    }
}

impl<N: Length> fmt::Debug for BitList<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BitList(")?;
        for bit in self.iter() {
            f.write_str(if bit { "1" } else { "0" })?;
        }
        f.write_str(")")
    }
}

impl<N> PartialEq for BitList<N> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.bytes == other.bytes
    }
}

impl<N> Eq for BitList<N> {}

impl<N> Hash for BitList<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.bytes.hash(state);
    }
}

impl<N: Length> Ssz for BitList<N> {
    const FIXED_SIZE: Option<usize> = None;

    fn encoded_len(&self) -> usize {
        // The sentinel needs one more bit, which opens a new byte when the length is a multiple of 8.
        self.len / 8 + 1
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&self.bytes);
        out.resize(start + self.encoded_len(), 0);
        out[start + self.len / 8] |= 1 << (self.len % 8);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Invariant: the last byte holds the sentinel, so it is never zero.
        let Some((&last, _)) = bytes.split_last() else {
            return Err(DecodeError::MissingSentinel);
        };
        if last == 0 {
            return Err(DecodeError::MissingSentinel);
        }

        // The sentinel is the highest set bit of the last byte.
        let sentinel = 7 - last.leading_zeros() as usize;
        let len = (bytes.len() - 1) * 8 + sentinel;
        if len > N::LEN {
            return Err(DecodeError::TooManyElements {
                limit: N::LEN,
                actual: len,
            });
        }

        // Strip the sentinel, and drop its byte when it held no real bits.
        let mut packed = bytes.to_vec();
        packed.truncate(len.div_ceil(8));
        if let Some(byte) = packed.get_mut(len / 8) {
            *byte &= !(1 << sentinel);
        }

        Ok(Self {
            bytes: packed,
            len,
            limit: PhantomData,
        })
    }

    fn hash_tree_root(&self) -> Root {
        Merkleizer::root_of_bytes(&self.bytes, N::LEN.div_ceil(8)).mix_in_length(self.len)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::Const;

    type Bits = BitList<Const<16>>;

    #[test]
    fn sentinel_follows_the_last_bit() {
        // Fixture state: bits 1 1 0, so the sentinel lands on bit 3.
        let mut bits = Bits::with_len(3).unwrap();
        bits.set(0, true);
        bits.set(1, true);

        assert_eq!(bits.encode(), [0b0000_1011]);
    }

    #[test]
    fn full_byte_pushes_the_sentinel_into_a_new_byte() {
        // Eight bits fill the first byte, so the sentinel opens a second one.
        let bits = Bits::with_len(8).unwrap();

        assert_eq!(bits.encode(), [0, 1]);
        assert_eq!(Bits::decode(&[0, 1]), Ok(bits));
    }

    #[test]
    fn missing_sentinel_is_rejected() {
        assert_eq!(Bits::decode(&[]), Err(DecodeError::MissingSentinel));
        assert_eq!(Bits::decode(&[1, 0]), Err(DecodeError::MissingSentinel));
    }

    #[test]
    fn length_over_the_limit_is_rejected() {
        // A sentinel at bit 1 of the third byte means 17 bits, one past the limit of 16.
        assert_eq!(
            Bits::decode(&[0, 0, 0b10]),
            Err(DecodeError::TooManyElements {
                limit: 16,
                actual: 17
            })
        );
    }

    #[test]
    fn union_and_subset_follow_set_semantics() {
        let mut left = Bits::with_len(4).unwrap();
        left.set(0, true);
        let mut right = Bits::with_len(4).unwrap();
        right.set(2, true);

        let both = left.union(&right).unwrap();

        assert!(left.is_subset_of(&both));
        assert!(!both.is_subset_of(&left));
        assert!(!left.intersects(&right));
        assert_eq!(both.count_ones(), 2);
    }

    proptest! {
        #[test]
        fn round_trips(bits in proptest::collection::vec(any::<bool>(), 0..=16)) {
            let mut list = Bits::with_len(bits.len()).unwrap();
            for (index, bit) in bits.iter().enumerate() {
                list.set(index, *bit);
            }

            prop_assert_eq!(Bits::decode(&list.encode()), Ok(list));
        }

        #[test]
        fn accepted_bytes_re_encode_identically(bytes in proptest::collection::vec(any::<u8>(), 0..4)) {
            if let Ok(list) = Bits::decode(&bytes) {
                prop_assert_eq!(list.encode(), bytes);
            }
        }
    }
}
