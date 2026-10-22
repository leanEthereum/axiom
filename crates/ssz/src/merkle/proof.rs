//! Single-leaf merkle proofs.

use crate::{GeneralizedIndex, Root, ZeroHashes};

/// Sibling roots on the path from a leaf up to the root, ordered bottom first.
///
/// See `is_valid_merkle_branch` in the phase0 beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MerkleProof {
    /// One sibling per level, the leaf's sibling first.
    pub branch: Vec<Root>,
}

impl MerkleProof {
    /// Proof for one leaf of a tree of the given depth.
    ///
    /// Leaves beyond the given slice are zero, as in a padded collection.
    ///
    /// # Panics
    ///
    /// Panics when the position is outside the tree, or the leaves overflow it.
    #[must_use]
    pub fn generate(leaves: &[Root], depth: usize, position: usize) -> Self {
        assert!(
            depth < 64 && position < 1 << depth,
            "leaf is outside the tree"
        );
        assert!(
            leaves.len() <= 1 << depth,
            "too many leaves for the tree depth"
        );

        let mut branch = Vec::with_capacity(depth);
        let mut level = leaves.to_vec();
        let mut index = position;

        for height in 0..depth {
            // The sibling is a real node when present, otherwise a zero subtree.
            let sibling = level
                .get(index ^ 1)
                .copied()
                .unwrap_or_else(|| ZeroHashes::at(height));
            branch.push(sibling);

            // Hash the level in pairs, padding an odd tail with the zero subtree.
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [left, right] => Root::hash_pair(left, right),
                    [left] => Root::hash_pair(left, &ZeroHashes::at(height)),
                    _ => unreachable!("chunks of two yield one or two nodes"),
                })
                .collect();
            index /= 2;
        }

        Self { branch }
    }

    /// Root implied by this proof for a leaf at the given index.
    ///
    /// Returns nothing when the proof length does not match the index depth.
    #[must_use]
    pub fn compute_root(&self, leaf: Root, index: GeneralizedIndex) -> Option<Root> {
        if self.branch.len() != index.depth() as usize {
            return None;
        }

        // Walk up: an odd node is a right child, so its sibling goes on the left.
        let mut node = leaf;
        let mut position = index.get();
        for sibling in &self.branch {
            node = if position & 1 == 1 {
                Root::hash_pair(sibling, &node)
            } else {
                Root::hash_pair(&node, sibling)
            };
            position >>= 1;
        }
        Some(node)
    }

    /// Whether this proof places the leaf at the given index under the root.
    #[must_use]
    pub fn verify(&self, leaf: Root, index: GeneralizedIndex, root: Root) -> bool {
        self.compute_root(leaf, index) == Some(root)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::Merkleizer;

    fn leaves(count: usize) -> Vec<Root> {
        (0..count)
            .map(|i| Root([u8::try_from(i + 1).unwrap(); 32]))
            .collect()
    }

    fn root_of(leaves: &[Root], depth: usize) -> Root {
        let mut merkleizer = Merkleizer::with_depth(depth);
        for leaf in leaves {
            merkleizer.push(*leaf);
        }
        merkleizer.finish()
    }

    #[test]
    fn wrong_proof_length_has_no_root() {
        // A depth-3 index needs three siblings, and this proof carries two.
        let proof = MerkleProof {
            branch: vec![Root::ZERO; 2],
        };

        assert_eq!(
            proof.compute_root(Root::ZERO, GeneralizedIndex::at(3, 0)),
            None
        );
    }

    #[test]
    fn tampered_sibling_fails_verification() {
        // Fixture state: 5 leaves in a depth-3 tree, proving leaf 2.
        let leaves = leaves(5);
        let root = root_of(&leaves, 3);
        let mut proof = MerkleProof::generate(&leaves, 3, 2);

        // Mutation: flip one byte of the middle sibling.
        proof.branch[1].0[0] ^= 1;

        assert!(!proof.verify(leaves[2], GeneralizedIndex::at(3, 2), root));
    }

    proptest! {
        #[test]
        fn generated_proof_verifies(count in 1_usize..=16, depth in 4_usize..=6, seed: usize) {
            let leaves = leaves(count);
            let position = seed % (1 << depth);
            let root = root_of(&leaves, depth);

            let proof = MerkleProof::generate(&leaves, depth, position);

            // A position past the real leaves proves a zero padding leaf.
            let leaf = leaves.get(position).copied().unwrap_or(Root::ZERO);
            prop_assert!(proof.verify(leaf, GeneralizedIndex::at(depth, position as u64), root));
        }
    }
}
