//! The block header step.

use axiom_ssz::Ssz;
use axiom_types::{BeaconBlockHeader, Preset, Root};

use super::{BlockProcessor, Operation};
use crate::{BlockError, StateError};

impl<P: Preset> Operation<P> for BeaconBlockHeader {
    /// Checks the block's place in the chain, and records its header.
    ///
    /// The recorded state root stays empty here.
    /// The next slot fills it once the post-state root is known.
    ///
    /// See `process_block_header` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let state = &processor.state.beacon;
        if self.slot != state.slot {
            return Err(BlockError::SlotMismatch {
                block: self.slot,
                state: state.slot,
            });
        }
        if self.slot <= state.latest_block_header.slot {
            return Err(BlockError::NotNewerThanParent {
                block: self.slot,
                latest: state.latest_block_header.slot,
            });
        }
        let expected = state.beacon_proposer_index();
        if self.proposer_index != expected {
            return Err(BlockError::WrongProposer {
                claimed: self.proposer_index,
                expected,
            });
        }
        let parent = state.latest_block_header.hash_tree_root();
        if self.parent_root != parent {
            return Err(BlockError::ParentMismatch {
                claimed: self.parent_root,
                expected: parent,
            });
        }

        let state = &mut processor.state.beacon;
        state.latest_block_header = Self {
            state_root: Root::ZERO,
            ..self.clone()
        };

        let proposer = state.validators.get(self.proposer_index.as_usize()).ok_or(
            StateError::UnknownValidator {
                index: self.proposer_index,
                registry_size: state.validators.len(),
            },
        )?;
        if proposer.slashed {
            return Err(BlockError::ProposerSlashed(self.proposer_index));
        }
        Ok(())
    }
}
