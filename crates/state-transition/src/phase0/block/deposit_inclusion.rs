//! Deposit inclusion: proving a deposit sits in the contract tree the state adopted.

use axiom_ssz::{GeneralizedIndex, MerkleProof, Ssz};
use axiom_types::{
    Root, accessors::CoreState, constants::DEPOSIT_CONTRACT_TREE_DEPTH, phase0::Deposit,
};

use crate::{BlockError, StateError};

/// A deposit from the contract, whose inclusion a block proves.
///
/// Every fork that keeps contract deposits checks inclusion this way.
/// Only what happens to the deposit afterwards changed.
#[derive(Clone, Copy, Debug)]
pub struct DepositInclusion<'a>(pub &'a Deposit);

impl DepositInclusion<'_> {
    /// Checks the deposit is the next one in the contract tree, then consumes its index.
    ///
    /// The branch has one more level than the tree, for the length mixed into the root.
    /// Deposits apply in contract order, so the index is the state's deposit counter.
    /// See `process_deposit` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the branch does not lead to the adopted deposit root.
    pub fn consume<S: CoreState + ?Sized>(self, state: &mut S) -> Result<(), BlockError> {
        let index = state.eth1_deposit_index();
        let deposit_root = state.eth1_data().deposit_root;
        let invalid = BlockError::InvalidDepositProof {
            index,
            deposit_root,
        };
        // Threshold: the tree and its length mix-in span 33 levels, so larger indices have no leaf.
        let depth = DEPOSIT_CONTRACT_TREE_DEPTH + 1;
        if index >= 1 << depth {
            return Err(invalid);
        }
        let proof = MerkleProof {
            branch: self.0.proof.iter().map(|node| Root(node.0)).collect(),
        };
        let leaf = self.0.data.hash_tree_root();
        if !proof.verify(leaf, GeneralizedIndex::at(depth, index), deposit_root) {
            return Err(invalid);
        }
        let counter = state.eth1_deposit_index_mut();
        *counter = counter.checked_add(1).ok_or(StateError::Overflow {
            quantity: "eth1 deposit index",
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Bytes32, Gwei, Minimal,
        electra::BeaconState,
        phase0::{DepositData, Eth1Data},
    };

    use super::*;

    fn contract() -> (Deposit, Root) {
        // Fixture state: a contract of two deposits, 1 ETH then 32 ETH.
        let deposits = [Gwei(1_000_000_000), Gwei(32_000_000_000)].map(|amount| DepositData {
            amount,
            ..DepositData::default()
        });
        let leaves: Vec<Root> = deposits.iter().map(Ssz::hash_tree_root).collect();
        let mut branch = MerkleProof::generate(&leaves, DEPOSIT_CONTRACT_TREE_DEPTH, 1).branch;

        // The contract root mixes in the count of 2, so the top sibling is that length chunk.
        let mut length = [0; 32];
        length[0] = 2;
        branch.push(Root(length));
        let mut proof = Deposit::default().proof;
        for (slot, node) in proof.iter_mut().zip(&branch) {
            *slot = Bytes32(node.0);
        }
        let root = MerkleProof { branch }
            .compute_root(
                leaves[1],
                GeneralizedIndex::at(DEPOSIT_CONTRACT_TREE_DEPTH + 1, 1),
            )
            .unwrap();
        let deposit = Deposit {
            proof,
            data: deposits[1].clone(),
        };
        (deposit, root)
    }

    fn state(deposit_root: Root, deposit_index: u64) -> BeaconState<Minimal> {
        BeaconState {
            eth1_data: Eth1Data {
                deposit_root,
                deposit_count: 2,
                ..Eth1Data::default()
            },
            eth1_deposit_index: deposit_index,
            ..BeaconState::default()
        }
    }

    #[test]
    fn the_next_deposit_is_consumed() {
        // Fixture state: deposit 0 bridged, so deposit 1 is next.
        let (deposit, root) = contract();
        let mut state = state(root, 1);

        DepositInclusion(&deposit).consume(&mut state).unwrap();

        // The counter moves past deposit 1.
        assert_eq!(state.eth1_deposit_index, 2);
    }

    #[test]
    fn a_deposit_out_of_order_is_rejected() {
        // Fixture state: nothing bridged, so deposit 0 is next, not deposit 1.
        let (deposit, root) = contract();
        let mut state = state(root, 0);

        // The branch of deposit 1 does not lead to the root from position 0.
        assert_eq!(
            DepositInclusion(&deposit).consume(&mut state),
            Err(BlockError::InvalidDepositProof {
                index: 0,
                deposit_root: root,
            })
        );
        assert_eq!(state.eth1_deposit_index, 0);
    }
}
