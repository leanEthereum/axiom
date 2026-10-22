//! A fixed-length bit set over the members of one committee.

use std::iter;

use axiom_ssz::{BitList, Length, ProgressiveBitList};

use crate::PoolError;

/// Bits of a fixed length, packed into 64-bit words.
///
/// Packing compares whole words: a committee of 512 members is eight words per operation.
///
/// # Invariants
///
/// Bits past the length are always zero, so counts and subset tests never see them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bits {
    /// Number of bits.
    len: usize,
    /// The bits, least significant first within each word.
    words: Vec<u64>,
}

impl Bits {
    /// All-zero bits of a length.
    #[must_use]
    pub fn zeros(len: usize) -> Self {
        Self {
            len,
            words: vec![0; len.div_ceil(64)],
        }
    }

    /// Bits read from an iterator of booleans.
    pub fn from_bools(bools: impl ExactSizeIterator<Item = bool>) -> Self {
        let mut bits = Self::zeros(bools.len());
        for (position, bit) in bools.enumerate() {
            if bit {
                bits.set(position);
            }
        }
        bits
    }

    /// Bits with exactly one position set.
    ///
    /// The position must lie below the length.
    #[must_use]
    pub fn single(len: usize, position: usize) -> Self {
        let mut bits = Self::zeros(len);
        bits.set(position);
        bits
    }

    /// Number of bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bit at a position, false past the length.
    #[must_use]
    pub fn get(&self, position: usize) -> bool {
        position < self.len && self.words[position / 64] >> (position % 64) & 1 == 1
    }

    /// Sets the bit at a position; positions past the length are ignored.
    pub fn set(&mut self, position: usize) {
        if position < self.len {
            self.words[position / 64] |= 1 << (position % 64);
        }
    }

    /// Number of set bits.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Whether no bit is set.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Whether every set bit is also set in the other bits of the same length.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .words
                .iter()
                .zip(&other.words)
                .all(|(mine, theirs)| mine & !theirs == 0)
    }

    /// Whether no bit is set in both.
    #[must_use]
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.words
            .iter()
            .zip(&other.words)
            .all(|(mine, theirs)| mine & theirs == 0)
    }

    /// Sets every bit the other bits set.
    pub fn union_with(&mut self, other: &Self) {
        for (mine, theirs) in self.words.iter_mut().zip(&other.words) {
            *mine |= theirs;
        }
    }

    /// Positions of the set bits, in increasing order.
    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        Self::ones_of(&self.words)
    }

    /// Positions set here and not in the other bits, in increasing order.
    pub fn ones_outside<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = usize> + 'a {
        let words = self
            .words
            .iter()
            .zip(other.words.iter().chain(iter::repeat(&0)))
            .map(|(mine, theirs)| mine & !theirs);
        words.enumerate().flat_map(|(index, word)| WordOnes {
            base: index * 64,
            word,
        })
    }

    /// The bits as booleans, one per position.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = bool> + '_ {
        (0..self.len).map(|position| self.get(position))
    }

    /// The bits as a bounded SSZ bit list.
    ///
    /// # Errors
    ///
    /// Fails when the length exceeds the list's bound.
    pub fn to_bit_list<N: Length>(&self) -> Result<BitList<N>, PoolError> {
        let mut list = BitList::with_len(self.len).map_err(|_| PoolError::TooManySigners {
            count: self.len,
            limit: N::LEN,
        })?;
        for position in self.ones() {
            list.set(position, true);
        }
        Ok(list)
    }

    /// The bits as an unbounded SSZ bit list.
    #[must_use]
    pub fn to_progressive_bit_list(&self) -> ProgressiveBitList {
        let mut list = ProgressiveBitList::with_len(self.len);
        for position in self.ones() {
            list.set(position, true);
        }
        list
    }

    /// Set positions of a slice of words.
    fn ones_of(words: &[u64]) -> impl Iterator<Item = usize> + '_ {
        words.iter().enumerate().flat_map(|(index, word)| WordOnes {
            base: index * 64,
            word: *word,
        })
    }
}

/// The set positions of one word, lowest first.
#[derive(Clone, Debug)]
struct WordOnes {
    /// Position of the word's lowest bit.
    base: usize,
    /// Bits not yet returned.
    word: u64,
}

impl Iterator for WordOnes {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.word == 0 {
            return None;
        }
        let offset = self.word.trailing_zeros() as usize;
        // Clears the lowest set bit.
        self.word &= self.word - 1;
        Some(self.base + offset)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn positions_past_the_length_are_never_set() {
        // A 70-bit set spans two words; position 70 would sit in the second.
        let mut bits = Bits::zeros(70);
        bits.set(69);
        bits.set(70);
        assert_eq!(bits.ones().collect::<Vec<_>>(), [69]);
        assert_eq!(bits.count_ones(), 1);
        assert!(!bits.get(70));
    }

    proptest! {
        #[test]
        fn word_operations_match_the_boolean_reference(
            left in proptest::collection::vec(any::<bool>(), 0..200),
            seed in any::<u64>(),
        ) {
            // The right side flips a pseudo-random subset of the left's bits.
            let right: Vec<bool> = left
                .iter()
                .enumerate()
                .map(|(index, bit)| bit ^ (seed.rotate_left(index as u32) & 1 == 1))
                .collect();
            let a = Bits::from_bools(left.iter().copied());
            let b = Bits::from_bools(right.iter().copied());
            let pairs = || left.iter().zip(&right);

            prop_assert_eq!(a.count_ones(), left.iter().filter(|bit| **bit).count());
            prop_assert_eq!(a.is_subset_of(&b), pairs().all(|(x, y)| !x || *y));
            prop_assert_eq!(a.is_disjoint(&b), pairs().all(|(x, y)| !(x & y)));
            let outside: Vec<usize> = pairs()
                .enumerate()
                .filter(|(_, (x, y))| **x && !**y)
                .map(|(index, _)| index)
                .collect();
            prop_assert_eq!(a.ones_outside(&b).collect::<Vec<_>>(), outside);
            let mut union = a.clone();
            union.union_with(&b);
            let expected: Vec<bool> = pairs().map(|(x, y)| x | y).collect();
            prop_assert_eq!(union.iter().collect::<Vec<_>>(), expected);
        }
    }
}
