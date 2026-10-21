//! Roots of all-zero subtrees.

use std::sync::LazyLock;

use crate::Root;

/// Deepest tree the table covers.
///
/// A list limit is at most 2^64 chunks, so no tree is deeper than 64 levels.
const MAX_DEPTH: usize = 64;

/// Table of zero-subtree roots, built once on first use.
static TABLE: LazyLock<[Root; MAX_DEPTH + 1]> = LazyLock::new(|| {
    let mut table = [Root::ZERO; MAX_DEPTH + 1];
    // Each level is the hash of two copies of the level below.
    for depth in 1..=MAX_DEPTH {
        table[depth] = Root::hash_pair(&table[depth - 1], &table[depth - 1]);
    }
    table
});

/// Roots of all-zero subtrees, by depth.
///
/// A list padded to its limit is mostly empty.
/// Reading the padding's roots from this table turns a 2^40 leaf tree into 40 hashes.
#[derive(Clone, Copy, Debug)]
pub struct ZeroHashes;

impl ZeroHashes {
    /// Root of an all-zero subtree with 2^depth leaves.
    ///
    /// # Panics
    ///
    /// Panics when the depth exceeds 64.
    #[must_use]
    pub fn at(depth: usize) -> Root {
        TABLE[depth]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_zero_is_the_zero_chunk() {
        assert_eq!(ZeroHashes::at(0), Root::ZERO);
    }

    #[test]
    fn each_level_hashes_two_copies_of_the_previous() {
        for depth in 1..=MAX_DEPTH {
            let below = ZeroHashes::at(depth - 1);
            assert_eq!(ZeroHashes::at(depth), Root::hash_pair(&below, &below));
        }
    }
}
