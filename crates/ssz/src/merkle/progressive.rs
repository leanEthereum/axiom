//! Progressive merkleization, the tree shape of progressive lists and containers.

use std::mem;

use crate::{BYTES_PER_CHUNK, GeneralizedIndex, MerkleProof, Merkleizer, Root};

/// Builds the root of a progressive tree from leaves fed one at a time.
///
/// # Overview
///
/// A progressive tree has no capacity fixed in advance.
/// Its leaves fill binary subtrees of 1, 4, 16, 64, and so on leaves, in order.
/// Each subtree is the left child of a spine node, whose right child holds every later leaf.
/// The spine ends in a zero chunk after the last subtree that holds a leaf.
///
/// ```text
/// root = hash(subtree_0, hash(subtree_1, hash(subtree_2, zero)))
/// ```
///
/// A leaf keeps its generalized index as the tree grows, so proofs stay stable.
/// See EIP-7916.
///
/// # Performance
///
/// One binary merkleizer streams the subtree being filled.
/// Each finished subtree costs one stored root, at most 32 of them.
#[derive(Clone, Debug)]
pub struct ProgressiveMerkleizer {
    /// Roots of the subtrees already full, in order.
    full: Vec<Root>,
    /// The subtree being filled.
    current: Merkleizer,
    /// Leaves pushed into the subtree being filled.
    current_len: u64,
    /// Depth of the subtree being filled, twice its index along the spine.
    current_depth: usize,
    /// Bytes of a partially filled chunk, for packed basic values.
    partial: [u8; BYTES_PER_CHUNK],
    /// Number of bytes used in the partial chunk.
    partial_len: usize,
}

impl Default for ProgressiveMerkleizer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressiveMerkleizer {
    /// A merkleizer with no leaves.
    #[must_use]
    pub fn new() -> Self {
        Self {
            full: Vec::new(),
            current: Merkleizer::with_depth(0),
            current_len: 0,
            current_depth: 0,
            partial: [0; BYTES_PER_CHUNK],
            partial_len: 0,
        }
    }

    /// Adds one leaf.
    pub fn push(&mut self, leaf: Root) {
        // Invariant: leaves and packed bytes never mix in one tree.
        debug_assert_eq!(self.partial_len, 0, "a packed chunk is half written");
        if self.current_len == 1 << self.current_depth {
            // The subtree is full: freeze its root and open one four times larger.
            self.current_depth += 2;
            let next = Merkleizer::with_depth(self.current_depth);
            self.full
                .push(mem::replace(&mut self.current, next).finish());
            self.current_len = 0;
        }
        self.current.push(leaf);
        self.current_len += 1;
    }

    /// Appends packed bytes, emitting a leaf each time a chunk fills.
    pub fn push_bytes(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let take = bytes.len().min(BYTES_PER_CHUNK - self.partial_len);
            self.partial[self.partial_len..self.partial_len + take].copy_from_slice(&bytes[..take]);
            self.partial_len += take;
            bytes = &bytes[take..];
            if self.partial_len == BYTES_PER_CHUNK {
                self.flush_partial();
            }
        }
    }

    /// Root of the tree.
    #[must_use]
    pub fn finish(mut self) -> Root {
        if self.partial_len > 0 {
            // The unused tail of the last chunk is zero, as the spec's padding requires.
            self.partial[self.partial_len..].fill(0);
            self.flush_partial();
        }
        if self.current_len > 0 {
            self.full.push(self.current.finish());
        }

        // Fold the spine from its zero end back to the root.
        self.full
            .iter()
            .rev()
            .fold(Root::ZERO, |rest, subtree| Root::hash_pair(subtree, &rest))
    }

    /// Generalized index of a leaf within a progressive tree.
    ///
    /// # Algorithm
    ///
    /// 1. Find the subtree holding the leaf, and the leaf's position inside it.
    /// 2. Walk right along the spine once per earlier subtree.
    /// 3. Step left into the subtree, then down to the leaf.
    ///
    /// # Panics
    ///
    /// Panics when the index would not fit in 64 bits, past about 2^31 leaves.
    #[must_use]
    pub const fn leaf_index(position: u64) -> GeneralizedIndex {
        let (subtree, local) = Self::locate(position);
        let mut index = GeneralizedIndex::ROOT;
        let mut step = 0;
        while step < subtree {
            index = index.concat(GeneralizedIndex::new(3));
            step += 1;
        }
        index
            .concat(GeneralizedIndex::new(2))
            .concat(GeneralizedIndex::at(2 * subtree, local))
    }

    /// Proof for one leaf of the progressive tree over the given leaves.
    ///
    /// # Panics
    ///
    /// Panics when the position is not one of the leaves.
    #[must_use]
    pub fn proof(leaves: &[Root], position: usize) -> MerkleProof {
        assert!(position < leaves.len(), "leaf is outside the tree");

        // Phase 1: the root of every subtree, in order along the spine.
        let mut subtree_roots = Vec::new();
        let mut start = 0;
        let mut depth = 0;
        while start < leaves.len() {
            let end = leaves.len().min(start + (1 << depth));
            let mut merkleizer = Merkleizer::with_depth(depth);
            for leaf in &leaves[start..end] {
                merkleizer.push(*leaf);
            }
            subtree_roots.push(merkleizer.finish());
            start = end;
            depth += 2;
        }

        // Phase 2: siblings inside the leaf's own subtree.
        let (subtree, local) = Self::locate(position as u64);
        let offset = Self::offset(subtree) as usize;
        let end = leaves.len().min(offset + (1 << (2 * subtree)));
        let mut proof = MerkleProof::generate(&leaves[offset..end], 2 * subtree, local as usize);

        // Phase 3: the rest of the spine to the right, then each earlier subtree on the left.
        let rest = subtree_roots[subtree + 1..]
            .iter()
            .rev()
            .fold(Root::ZERO, |rest, root| Root::hash_pair(root, &rest));
        proof.branch.push(rest);
        proof
            .branch
            .extend(subtree_roots[..subtree].iter().rev().copied());
        proof
    }

    /// The subtree holding a leaf, and the leaf's position inside it.
    const fn locate(position: u64) -> (usize, u64) {
        let mut subtree = 0;
        while Self::offset(subtree + 1) <= position {
            subtree += 1;
        }
        (subtree, position - Self::offset(subtree))
    }

    /// Leaves in every subtree before the given one.
    ///
    /// The subtrees hold 4^0, 4^1, and so on leaves, so the offset is a geometric sum.
    ///
    /// ```text
    /// offset(k) = (4^k - 1) / 3
    /// ```
    const fn offset(subtree: usize) -> u64 {
        ((1_u128 << (2 * subtree)) - 1) as u64 / 3
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
    use crate::ZeroHashes;

    /// Reference merkleization, written the way EIP-7916 describes it.
    fn reference_root(chunks: &[Root], num_leaves: usize) -> Root {
        if chunks.is_empty() {
            return Root::ZERO;
        }
        let split = num_leaves.min(chunks.len());
        let mut subtree = Merkleizer::with_limit(num_leaves);
        for chunk in &chunks[..split] {
            subtree.push(*chunk);
        }
        Root::hash_pair(
            &subtree.finish(),
            &reference_root(&chunks[split..], num_leaves * 4),
        )
    }

    fn leaves(count: usize) -> Vec<Root> {
        (0..count)
            .map(|index| Root([index as u8 + 1; 32]))
            .collect()
    }

    fn root_of(chunks: &[Root]) -> Root {
        let mut merkleizer = ProgressiveMerkleizer::new();
        for chunk in chunks {
            merkleizer.push(*chunk);
        }
        merkleizer.finish()
    }

    #[test]
    fn empty_tree_is_the_zero_chunk() {
        assert_eq!(ProgressiveMerkleizer::new().finish(), Root::ZERO);
    }

    #[test]
    fn single_leaf_hangs_left_of_a_zero_spine() {
        // One leaf fills the first subtree, and the spine ends right after it.
        let leaf = Root([7; 32]);

        assert_eq!(root_of(&[leaf]), Root::hash_pair(&leaf, &Root::ZERO));
    }

    #[test]
    fn second_leaf_opens_a_four_leaf_subtree() {
        // Leaves 0 and 1: the second subtree holds one real leaf and three zero slots.
        let chunks = leaves(2);
        let subtree = Root::hash_pair(
            &Root::hash_pair(&chunks[1], &Root::ZERO),
            &ZeroHashes::at(1),
        );
        let expected = Root::hash_pair(&chunks[0], &Root::hash_pair(&subtree, &Root::ZERO));

        assert_eq!(root_of(&chunks), expected);
    }

    #[test]
    fn leaf_indices_follow_the_spine() {
        // Leaf 0: left of the root, node 2.
        assert_eq!(ProgressiveMerkleizer::leaf_index(0).get(), 2);
        // Leaves 1 to 4: right once (3), left (6), then two levels down: 24 to 27.
        assert_eq!(ProgressiveMerkleizer::leaf_index(1).get(), 24);
        assert_eq!(ProgressiveMerkleizer::leaf_index(4).get(), 27);
        // Leaf 5: right twice (7), left (14), then four levels down: 224.
        assert_eq!(ProgressiveMerkleizer::leaf_index(5).get(), 224);
    }

    #[test]
    fn packed_bytes_split_across_calls_match_one_call() {
        // 70 bytes span three chunks, the last one zero-padded.
        let bytes: Vec<u8> = (0..70).collect();
        let mut whole = ProgressiveMerkleizer::new();
        whole.push_bytes(&bytes);
        let mut split = ProgressiveMerkleizer::new();
        split.push_bytes(&bytes[..5]);
        split.push_bytes(&bytes[5..40]);
        split.push_bytes(&bytes[40..]);

        assert_eq!(whole.finish(), split.finish());
    }

    proptest! {
        #[test]
        fn streaming_root_equals_reference(count in 0_usize..=100) {
            let chunks = leaves(count);

            prop_assert_eq!(root_of(&chunks), reference_root(&chunks, 1));
        }

        #[test]
        fn every_leaf_proof_verifies(count in 1_usize..=90, seed: usize) {
            let chunks = leaves(count);
            let position = seed % count;

            let proof = ProgressiveMerkleizer::proof(&chunks, position);

            prop_assert!(proof.verify(
                chunks[position],
                ProgressiveMerkleizer::leaf_index(position as u64),
                root_of(&chunks)
            ));
        }
    }
}
