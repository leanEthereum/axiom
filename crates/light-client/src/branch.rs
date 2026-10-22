//! A merkle branch at a fixed position, as light client data carries it.

use axiom_ssz::{GeneralizedIndex, MerkleProof, Root};
use axiom_types::Bytes32;

use crate::LightClientError;

/// The sibling nodes from a leaf at a generalized index up to a root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Branch<'a> {
    /// The siblings, from the leaf's level upward.
    nodes: &'a [Bytes32],
    /// Where the leaf sits in the tree.
    gindex: u64,
}

impl<'a> Branch<'a> {
    /// A branch for a leaf at a generalized index.
    pub(crate) const fn new(nodes: &'a [Bytes32], gindex: u64) -> Self {
        Self { nodes, gindex }
    }

    /// Checks that the branch carries a leaf up to a root.
    ///
    /// # Errors
    ///
    /// Fails when the branch does not reach the root.
    pub(crate) fn proves(&self, leaf: Root, root: Root) -> Result<(), LightClientError> {
        let proof = MerkleProof {
            branch: self.nodes.iter().map(|node| Root(node.0)).collect(),
        };
        if proof.verify(leaf, GeneralizedIndex::new(self.gindex), root) {
            Ok(())
        } else {
            Err(LightClientError::InvalidBranch)
        }
    }
}
