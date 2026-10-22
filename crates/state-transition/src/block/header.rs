//! The block header step.

use axiom_ssz::Ssz;
use axiom_types::{BeaconBlock, BeaconBlockHeader, Preset, Root};

use super::BlockProcessor;
use crate::{BlockError, StateError};

impl<P: Preset> BlockProcessor<'_, P> {
    /// Checks the block's place in the chain, and records its header.
    ///
    /// The header's state root stays empty here.
    /// The next slot fills it once the post-state root is known.
    ///
    /// See `process_block_header` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the slot, proposer, or parent is wrong, or the proposer is slashed.
    pub fn process_block_header(&mut self, block: &BeaconBlock<P>) -> Result<(), BlockError> {
        let state = &self.state.beacon;
        if block.slot != state.slot {
            return Err(BlockError::SlotMismatch {
                block: block.slot,
                state: state.slot,
            });
        }
        if block.slot <= state.latest_block_header.slot {
            return Err(BlockError::NotNewerThanParent);
        }
        let expected = state.beacon_proposer_index();
        if block.proposer_index != expected {
            return Err(BlockError::WrongProposer {
                claimed: block.proposer_index,
                expected,
            });
        }
        let parent = state.latest_block_header.hash_tree_root();
        if block.parent_root != parent {
            return Err(BlockError::ParentMismatch {
                claimed: block.parent_root,
                expected: parent,
            });
        }

        let state = &mut self.state.beacon;
        state.latest_block_header = BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: Root::ZERO,
            body_root: block.body.hash_tree_root(),
        };

        let proposer = state
            .validators
            .get(block.proposer_index.as_usize())
            .ok_or(StateError::UnknownValidator(block.proposer_index))?;
        if proposer.slashed {
            return Err(BlockError::ProposerSlashed(block.proposer_index));
        }
        Ok(())
    }
}
