//! Where each element of a persistent sequence lives, and the tree its packs form.

use crate::{BYTES_PER_CHUNK, Ssz};

/// Height of a pack's subtree: each pack holds the elements of 2^6 leaves.
///
/// A pack is the unit of sharing and of re-hashing.
/// An edit copies and re-hashes one pack, so small packs keep edits cheap.
/// Every root folds one cached root per pack, so large packs keep that fold short.
///
/// At 64 leaves, a pack holds 64 validators, 256 balances, or 2048 participation flags.
/// A million-validator registry then folds 16384 pack roots.
pub(crate) const PACK_HEIGHT: usize = 6;

/// The tree shape a sequence's elements hash into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A binary tree of a fixed depth, sized for a vector's length or a list's limit.
    Binary {
        /// Depth of the tree, counted in leaves.
        depth: usize,
    },

    /// A progressive tree, whose subtrees hold 1, 4, 16, and so on leaves, see EIP-7916.
    Progressive,
}

/// How a sequence splits its elements into packs, and which subtree each pack is.
///
/// # Overview
///
/// Every pack but the first holds the elements of 2^h leaves, where h is the pack height.
/// Each such pack is one aligned subtree of the hash tree, so its root can be cached.
///
/// In a binary tree the first pack is a full pack too, so packs start at multiples of 2^h.
///
/// A progressive tree places its subtrees at leaf offsets (4^i - 1) / 3.
/// Those offsets agree modulo 2^h once 4^i reaches 2^h, so a shifted grid fits them all.
/// The first pack holds the small subtrees before that point, and every later pack is aligned.
///
/// ```text
/// first subtree of at least 2^h leaves:  m = ceil(h / 2)
/// leaves in the first pack:              (4^m - 1) / 3
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// The tree shape.
    pub(crate) shape: Shape,
    /// Elements per leaf: several packed basic values, or one composite value.
    pub(crate) per_leaf: usize,
    /// Height of every pack after the first, in leaves.
    pub(crate) pack_height: usize,
    /// Number of elements a full pack holds, as a power of two.
    pack_shift: u32,
    /// Number of elements the first pack holds.
    head_len: usize,
}

impl Layout {
    /// Layout of a binary tree sized for a vector's length or a list's limit.
    pub(crate) fn binary<T: Ssz>(depth: usize) -> Self {
        // A tree shorter than a pack is a single pack of its own height.
        let pack_height = PACK_HEIGHT.min(depth);
        let per_leaf = Self::per_leaf::<T>();
        let pack_len = per_leaf << pack_height;
        Self {
            shape: Shape::Binary { depth },
            per_leaf,
            pack_height,
            pack_shift: pack_len.trailing_zeros(),
            head_len: pack_len,
        }
    }

    /// Layout of a progressive tree.
    pub(crate) const fn progressive<T: Ssz>() -> Self {
        let per_leaf = Self::per_leaf::<T>();
        let pack_len = per_leaf << PACK_HEIGHT;
        Self {
            shape: Shape::Progressive,
            per_leaf,
            pack_height: PACK_HEIGHT,
            pack_shift: pack_len.trailing_zeros(),
            head_len: Self::subtree_offset(Self::head_subtrees()) * per_leaf,
        }
    }

    /// Number of progressive subtrees in the first pack, all smaller than a full pack.
    pub(crate) const fn head_subtrees() -> usize {
        PACK_HEIGHT.div_ceil(2)
    }

    /// Leaves before a progressive subtree, the sum of 4^j for every earlier subtree j.
    pub(crate) const fn subtree_offset(subtree: usize) -> usize {
        ((1 << (2 * subtree)) - 1) / 3
    }

    /// Pack holding an element, and the element's position inside it.
    #[inline]
    pub(crate) const fn locate(&self, index: usize) -> (usize, usize) {
        if index < self.head_len {
            (0, index)
        } else {
            let rest = index - self.head_len;
            (
                1 + (rest >> self.pack_shift),
                rest & ((1 << self.pack_shift) - 1),
            )
        }
    }

    /// Number of elements a pack holds when full.
    pub(crate) const fn capacity(&self, pack: usize) -> usize {
        if pack == 0 {
            self.head_len
        } else {
            1 << self.pack_shift
        }
    }

    /// Elements per leaf for an element type.
    const fn per_leaf<T: Ssz>() -> usize {
        match T::PACKED_SIZE {
            Some(size) => BYTES_PER_CHUNK / size,
            None => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Root;

    #[test]
    fn binary_packs_start_at_multiples_of_the_pack_length() {
        // u64 packs four per leaf, so a pack of 64 leaves holds 256 values.
        let layout = Layout::binary::<u64>(40);

        assert_eq!(layout.locate(0), (0, 0));
        assert_eq!(layout.locate(255), (0, 255));
        assert_eq!(layout.locate(256), (1, 0));
        assert_eq!(layout.locate(1000), (3, 232));
    }

    #[test]
    fn a_shallow_tree_is_one_pack_of_its_own_height() {
        // A depth-2 tree of roots has four leaves, below the pack height of 6.
        let layout = Layout::binary::<Root>(2);

        assert_eq!(layout.pack_height, 2);
        assert_eq!(layout.capacity(0), 4);
    }

    #[test]
    fn progressive_head_holds_the_subtrees_below_a_pack() {
        // Subtrees of 1, 4, and 16 leaves are smaller than a pack of 64: 21 leaves.
        // The fourth subtree starts at leaf 21 and fills exactly one pack.
        let layout = Layout::progressive::<Root>();

        assert_eq!(Layout::head_subtrees(), 3);
        assert_eq!(layout.capacity(0), 21);
        assert_eq!(layout.locate(20), (0, 20));
        assert_eq!(layout.locate(21), (1, 0));
        assert_eq!(layout.locate(85), (2, 0));
        assert_eq!(Layout::subtree_offset(4), 85);
    }

    #[test]
    fn packs_tile_the_indices_without_gaps() {
        // Walking every index, the pack grows by one exactly when the previous pack is full.
        for layout in [
            Layout::binary::<u8>(40),
            Layout::progressive::<u16>(),
            Layout::progressive::<Root>(),
        ] {
            let mut expected = (0, 0);
            for index in 0..5000 {
                assert_eq!(layout.locate(index), expected, "index {index}");
                expected.1 += 1;
                if expected.1 == layout.capacity(expected.0) {
                    expected = (expected.0 + 1, 0);
                }
            }
        }
    }
}
