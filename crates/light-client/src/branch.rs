//! A merkle branch at a fixed position, as light client data carries it.

use axiom_ssz::{GeneralizedIndex, Length, MerkleProof, Root, Vector};
use axiom_types::Bytes32;

use crate::LightClientError;

/// The sibling nodes from a leaf at a generalized index up to a root.
///
/// # Overview
///
/// A branch type has one fixed length per fork, but the index it proves may sit higher.
/// The spec then pads the branch with zero nodes in front, below the leaf.
/// Verification skips those zeros, so one branch type serves every depth up to its length.
///
/// See `normalize_merkle_branch` in the Electra light client fork logic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Branch<'a> {
    /// The siblings, from the leaf's level upward, after any zero padding.
    nodes: &'a [Bytes32],
    /// Where the leaf sits in the tree.
    gindex: GeneralizedIndex,
}

impl<'a> Branch<'a> {
    /// A branch for a leaf at a generalized index.
    pub(crate) const fn new(nodes: &'a [Bytes32], gindex: GeneralizedIndex) -> Self {
        Self { nodes, gindex }
    }

    /// Checks that the branch carries a leaf up to a root.
    ///
    /// See `is_valid_normalized_merkle_branch` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the padding is not zero, or the branch does not reach the root.
    pub(crate) fn proves(&self, leaf: Root, root: Root) -> Result<(), LightClientError> {
        if self.reaches(leaf, root) {
            Ok(())
        } else {
            Err(LightClientError::InvalidBranch {
                gindex: self.gindex.get(),
                root,
            })
        }
    }

    /// Whether the padding is zero and the rest carries the leaf up to the root.
    pub(crate) fn reaches(&self, leaf: Root, root: Root) -> bool {
        self.path()
            .is_some_and(|proof| proof.verify(leaf, self.gindex, root))
    }

    /// The nodes past the padding, as a proof of exactly the index's depth.
    fn path(&self) -> Option<MerkleProof> {
        let depth = self.gindex.depth() as usize;
        let extra = self.nodes.len().checked_sub(depth)?;
        let (padding, path) = self.nodes.split_at(extra);
        padding
            .iter()
            .all(|node| *node == Bytes32::ZERO)
            .then(|| MerkleProof {
                branch: path.iter().map(|node| Root(node.0)).collect(),
            })
    }

    /// Pads nodes with zeros in front to a branch type's fixed length.
    ///
    /// See `normalize_merkle_branch` in the Electra light client fork logic.
    ///
    /// # Errors
    ///
    /// Fails when there are more nodes than the branch holds.
    pub(crate) fn pad<N: Length>(
        nodes: &[Bytes32],
    ) -> Result<Vector<Bytes32, N>, LightClientError> {
        let extra = N::LEN
            .checked_sub(nodes.len())
            .ok_or(LightClientError::BranchTooLong {
                length: nodes.len(),
                capacity: N::LEN,
            })?;
        Ok(Vector::from_fn(|index| {
            index
                .checked_sub(extra)
                .map_or(Bytes32::ZERO, |position| nodes[position])
        }))
    }

    /// The nodes of a proof, as light client data stores them.
    pub(crate) fn nodes_of(proof: &MerkleProof) -> Vec<Bytes32> {
        proof.branch.iter().map(|node| Bytes32(node.0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Const;

    use super::*;

    #[test]
    fn a_branch_that_misses_its_root_names_the_position_and_root() {
        // Generalized index 2 is the left child of the root, so one sibling lifts the leaf.
        let leaf = Root([1; 32]);
        let sibling = Bytes32([2; 32]);
        let nodes = [sibling];
        let branch = Branch::new(&nodes, GeneralizedIndex::new(2));
        let root = Root::hash_pair(&leaf, &Root(sibling.0));
        assert_eq!(branch.proves(leaf, root), Ok(()));

        // Mutation: a root of all 3s, which no leaf and sibling hash to here.
        assert_eq!(
            branch.proves(leaf, Root([3; 32])),
            Err(LightClientError::InvalidBranch {
                gindex: 2,
                root: Root([3; 32]),
            })
        );
    }

    #[test]
    fn padding_must_be_zero_and_sits_in_front() {
        // Index 2 needs one sibling; a branch of three carries two zero nodes in front.
        let leaf = Root([1; 32]);
        let sibling = Bytes32([2; 32]);
        let root = Root::hash_pair(&leaf, &Root(sibling.0));
        let padded = Branch::pad::<Const<3>>(&[sibling]).unwrap();
        assert_eq!(padded.as_slice(), [Bytes32::ZERO, Bytes32::ZERO, sibling]);
        let gindex = GeneralizedIndex::new(2);
        assert!(Branch::new(&padded, gindex).reaches(leaf, root));

        // Mutation: a nonzero padding node, which the spec rejects even if the path is right.
        let dirty = [Bytes32([9; 32]), Bytes32::ZERO, sibling];
        assert!(!Branch::new(&dirty, gindex).reaches(leaf, root));

        // Four nodes do not fit a branch of three.
        assert_eq!(
            Branch::pad::<Const<3>>(&[sibling; 4]),
            Err(LightClientError::BranchTooLong {
                length: 4,
                capacity: 3,
            })
        );
    }
}
