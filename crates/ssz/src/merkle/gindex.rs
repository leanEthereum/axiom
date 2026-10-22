//! Generalized indices, the address of a node in a binary merkle tree.

use std::fmt;

/// Address of a node in a binary merkle tree.
///
/// The root is 1, and the children of node `i` are `2i` and `2i + 1`.
///
/// ```text
/// depth 0:   1
/// depth 1:   2 3
/// depth 2:   4 5 6 7
/// ```
///
/// The binary form reads as a path: after the leading 1, each bit picks left (0) or right (1).
/// See the consensus specs' `ssz/merkle-proofs.md`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GeneralizedIndex(u64);

impl GeneralizedIndex {
    /// The root of the tree.
    pub const ROOT: Self = Self(1);

    /// The node at a position within a level.
    ///
    /// # Panics
    ///
    /// Panics when the position does not fit in the level, or the depth exceeds 63.
    #[must_use]
    pub const fn at(depth: usize, position: u64) -> Self {
        assert!(depth < 64, "generalized index depth must be below 64");
        assert!(
            position < 1 << depth,
            "position exceeds the width of its level"
        );
        Self((1 << depth) | position)
    }

    /// The node with the given raw index.
    ///
    /// # Panics
    ///
    /// Panics on zero, which addresses no node.
    #[must_use]
    pub const fn new(index: u64) -> Self {
        assert!(index != 0, "generalized index zero addresses no node");
        Self(index)
    }

    /// The raw index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Distance from the root, which is the length of a proof for this node.
    #[must_use]
    pub const fn depth(self) -> u32 {
        self.0.ilog2()
    }

    /// Position of the node within its level, counted from the left.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.0 - (1 << self.depth())
    }

    /// The node reached by following another index's path from this node.
    ///
    /// This addresses a field of a field: the outer index finds the inner tree's root.
    ///
    /// # Panics
    ///
    /// Panics when the combined depth reaches 64.
    #[must_use]
    pub const fn concat(self, inner: Self) -> Self {
        let inner_depth = inner.depth();
        assert!(
            self.depth() + inner_depth < 64,
            "combined generalized index is too deep"
        );
        Self((self.0 << inner_depth) | inner.position())
    }
}

impl fmt::Debug for GeneralizedIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GeneralizedIndex({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_and_position_decompose_the_index() {
        // Node 13 = 0b1101 sits at depth 3, position 0b101 = 5.
        let index = GeneralizedIndex::new(13);

        assert_eq!(index.depth(), 3);
        assert_eq!(index.position(), 5);
        assert_eq!(GeneralizedIndex::at(3, 5), index);
    }

    #[test]
    fn concat_follows_the_inner_path_from_the_outer_node() {
        // Field 3 of a 4-field container is node 7 = 0b111.
        // Its field 1 in a 2-field container is node 3 = 0b11.
        //
        //     path 1|11 then 1 gives 0b1111 = 15.
        let outer = GeneralizedIndex::new(7);
        let inner = GeneralizedIndex::new(3);

        assert_eq!(outer.concat(inner), GeneralizedIndex::new(15));
    }

    #[test]
    fn root_is_depth_zero() {
        assert_eq!(GeneralizedIndex::ROOT.depth(), 0);
        assert_eq!(GeneralizedIndex::ROOT.position(), 0);
    }
}
