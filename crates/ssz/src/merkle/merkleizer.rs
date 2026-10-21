//! A streaming merkleizer, the engine behind every hash tree root.

use crate::{BYTES_PER_CHUNK, Root, ZeroHashes};

/// Deepest tree a merkleizer builds, matching the zero-hash table.
const MAX_DEPTH: usize = 64;

/// Builds the root of a binary tree from leaves fed one at a time.
///
/// # Overview
///
/// The spec's merkleization pads the leaves with zero chunks up to a power of two.
/// It then hashes pairs level by level until one root remains.
///
/// This merkleizer never materializes the padded tree.
/// It keeps at most one pending left node per level, like a binary counter.
///
/// ```text
/// leaves pushed: a b c           (depth 2, so 4 leaf slots)
///
/// pending after a:   level 0 = a
/// pending after b:   level 1 = h(a, b)
/// pending after c:   level 1 = h(a, b), level 0 = c
///
/// finish:            h( h(a, b), h(c, zero_0) )
/// ```
///
/// # Performance
///
/// One hash per internal node holding a real leaf, plus one per level for padding.
/// Memory is a fixed 65-entry stack, with no allocation.
#[derive(Clone, Debug)]
pub struct Merkleizer {
    /// Pending left node at each level, valid where the matching bit of the count is set.
    pending: [Root; MAX_DEPTH + 1],
    /// Number of leaves pushed so far.
    count: u64,
    /// Depth of the full tree, so it has 2^depth leaf slots.
    depth: usize,
    /// Bytes of a partially filled chunk, for packed basic values.
    partial: [u8; BYTES_PER_CHUNK],
    /// Number of bytes used in the partial chunk.
    partial_len: usize,
}

impl Merkleizer {
    /// Merkleizer for a tree with room for the given number of leaves.
    ///
    /// The depth is the smallest one whose leaf count reaches the limit.
    /// A limit of zero or one gives a single-leaf tree.
    #[must_use]
    pub fn with_limit(limit: usize) -> Self {
        Self::with_depth(Self::depth_for(limit))
    }

    /// Merkleizer for a tree of the given depth.
    ///
    /// # Panics
    ///
    /// Panics when the depth exceeds 64.
    #[must_use]
    pub fn with_depth(depth: usize) -> Self {
        assert!(depth <= MAX_DEPTH, "tree depth {depth} exceeds {MAX_DEPTH}");
        Self {
            pending: [Root::ZERO; MAX_DEPTH + 1],
            count: 0,
            depth,
            partial: [0; BYTES_PER_CHUNK],
            partial_len: 0,
        }
    }

    /// Depth of the smallest tree with at least the given number of leaves.
    #[must_use]
    pub const fn depth_for(limit: usize) -> usize {
        if limit <= 1 {
            0
        } else {
            (usize::BITS - (limit - 1).leading_zeros()) as usize
        }
    }

    /// Root of bytes packed into chunks, for a tree sized to hold the byte limit.
    ///
    /// This is the spec's merkleization of a packed byte vector or byte list's contents.
    #[must_use]
    pub fn root_of_bytes(bytes: &[u8], limit_bytes: usize) -> Root {
        let mut merkleizer = Self::with_limit(limit_bytes.div_ceil(BYTES_PER_CHUNK));
        merkleizer.push_bytes(bytes);
        merkleizer.finish()
    }

    /// Adds one leaf.
    ///
    /// # Panics
    ///
    /// Panics when the tree is already full, which means the caller's limit was wrong.
    pub fn push(&mut self, leaf: Root) {
        // Invariant: leaves and packed bytes never mix in one tree.
        debug_assert_eq!(self.partial_len, 0, "a packed chunk is half written");
        assert!(
            self.depth == MAX_DEPTH || self.count < (1_u64 << self.depth),
            "merkle tree of depth {} is full",
            self.depth
        );

        // Carry upward while the level already holds a left sibling.
        //
        //     count = 0b011 means levels 0 and 1 hold pending nodes.
        //     The new leaf pairs with level 0, then with level 1, and lands on level 2.
        let mut node = leaf;
        let mut level = 0;
        while self.count & (1 << level) != 0 {
            node = Root::hash_pair(&self.pending[level], &node);
            level += 1;
        }
        self.pending[level] = node;
        self.count += 1;
    }

    /// Appends packed bytes, emitting a leaf each time a chunk fills.
    pub fn push_bytes(&mut self, mut bytes: &[u8]) {
        // Top up a partial chunk first, so whole chunks then copy straight through.
        if self.partial_len > 0 {
            let take = bytes.len().min(BYTES_PER_CHUNK - self.partial_len);
            self.partial[self.partial_len..self.partial_len + take].copy_from_slice(&bytes[..take]);
            self.partial_len += take;
            bytes = &bytes[take..];
            if self.partial_len < BYTES_PER_CHUNK {
                return;
            }
            self.flush_partial();
        }

        let (chunks, tail) = bytes.as_chunks::<BYTES_PER_CHUNK>();
        for chunk in chunks {
            self.push(Root(*chunk));
        }

        // Keep the tail for the next call, or for zero-padding at the end.
        self.partial[..tail.len()].copy_from_slice(tail);
        self.partial_len = tail.len();
    }

    /// Root of the tree, with every missing leaf taken as zero.
    #[must_use]
    pub fn finish(mut self) -> Root {
        if self.partial_len > 0 {
            // The unused tail of the last chunk is zero, as the spec's padding requires.
            self.partial[self.partial_len..].fill(0);
            self.flush_partial();
        }

        // A full tree already holds its root at the top level.
        if self.depth < MAX_DEPTH && self.count == 1 << self.depth {
            return self.pending[self.depth];
        }

        // Fold the pending nodes upward, filling each missing right sibling with zeros.
        //
        //     A set bit at a level is a complete left subtree waiting for its right half.
        //     The running node is the root of everything pushed after that subtree.
        let mut node: Option<Root> = None;
        for level in 0..self.depth {
            let has_left = self.count & (1 << level) != 0;
            node = match (has_left, node) {
                (true, Some(right)) => Some(Root::hash_pair(&self.pending[level], &right)),
                (true, None) => Some(Root::hash_pair(
                    &self.pending[level],
                    &ZeroHashes::at(level),
                )),
                (false, Some(left)) => Some(Root::hash_pair(&left, &ZeroHashes::at(level))),
                (false, None) => None,
            };
        }

        // No leaf at all leaves the whole tree empty.
        node.unwrap_or_else(|| ZeroHashes::at(self.depth))
    }

    /// Emits the partial chunk as a leaf.
    fn flush_partial(&mut self) {
        let leaf = Root(self.partial);
        self.partial_len = 0;
        self.push(leaf);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Reference merkleization, written the way the spec describes it.
    ///
    /// It pads to a power of two and hashes level by level.
    fn reference_root(leaves: &[Root], depth: usize) -> Root {
        let mut level: Vec<Root> = leaves.to_vec();
        level.resize(1 << depth, Root::ZERO);
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[left, right]| Root::hash_pair(left, right))
                .collect();
        }
        level[0]
    }

    fn leaf(tag: u8) -> Root {
        Root([tag; 32])
    }

    #[test]
    fn depth_for_rounds_up_to_a_power_of_two() {
        // 0 and 1 leaf fit a single slot, 5 leaves need 8 slots.
        assert_eq!(Merkleizer::depth_for(0), 0);
        assert_eq!(Merkleizer::depth_for(1), 0);
        assert_eq!(Merkleizer::depth_for(2), 1);
        assert_eq!(Merkleizer::depth_for(5), 3);
        assert_eq!(Merkleizer::depth_for(8), 3);
        assert_eq!(Merkleizer::depth_for(1 << 40), 40);
    }

    #[test]
    fn empty_tree_is_the_zero_subtree() {
        assert_eq!(Merkleizer::with_depth(5).finish(), ZeroHashes::at(5));
    }

    #[test]
    fn single_leaf_of_depth_zero_is_itself() {
        let mut merkleizer = Merkleizer::with_depth(0);
        merkleizer.push(leaf(3));

        assert_eq!(merkleizer.finish(), leaf(3));
    }

    #[test]
    fn three_leaves_match_the_padded_tree() {
        // Fixture state: leaves a, b, c in a depth-2 tree, so one zero leaf pads it.
        //
        //     root = h( h(a, b), h(c, 0) )
        let mut merkleizer = Merkleizer::with_depth(2);
        for tag in 1..=3 {
            merkleizer.push(leaf(tag));
        }

        let expected = Root::hash_pair(
            &Root::hash_pair(&leaf(1), &leaf(2)),
            &Root::hash_pair(&leaf(3), &Root::ZERO),
        );
        assert_eq!(merkleizer.finish(), expected);
    }

    #[test]
    fn packed_bytes_split_across_calls_match_one_call() {
        // 40 bytes span one full chunk and 8 bytes of a second one.
        let bytes: Vec<u8> = (0..40).collect();

        let mut split = Merkleizer::with_limit(4);
        split.push_bytes(&bytes[..13]);
        split.push_bytes(&bytes[13..]);

        assert_eq!(split.finish(), Merkleizer::root_of_bytes(&bytes, 128));
    }

    #[test]
    #[should_panic(expected = "is full")]
    fn pushing_past_the_limit_panics() {
        // A depth-1 tree has two slots, so a third leaf breaks the caller's invariant.
        let mut merkleizer = Merkleizer::with_depth(1);
        for tag in 0..3 {
            merkleizer.push(leaf(tag));
        }
    }

    proptest! {
        #[test]
        fn streaming_root_equals_reference(count in 0_usize..=64, depth in 6_usize..=8) {
            let leaves: Vec<Root> = (0..count).map(|i| leaf(u8::try_from(i).unwrap())).collect();

            let mut merkleizer = Merkleizer::with_depth(depth);
            for leaf in &leaves {
                merkleizer.push(*leaf);
            }

            prop_assert_eq!(merkleizer.finish(), reference_root(&leaves, depth));
        }

        #[test]
        fn deep_tree_extends_the_shallow_root_with_zero_hashes(count in 1_usize..=16) {
            // Padding a 16-slot tree out to 2^40 slots wraps its root in 36 zero siblings.
            let leaves: Vec<Root> = (0..count).map(|i| leaf(u8::try_from(i).unwrap())).collect();

            let mut deep = Merkleizer::with_depth(40);
            for leaf in &leaves {
                deep.push(*leaf);
            }

            let mut expected = reference_root(&leaves, 4);
            for level in 4..40 {
                expected = Root::hash_pair(&expected, &ZeroHashes::at(level));
            }
            prop_assert_eq!(deep.finish(), expected);
        }
    }
}
