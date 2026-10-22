//! The block header step.

use axiom_ssz::Ssz;
use axiom_types::{Root, phase0::BeaconBlockHeader};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork> Operation<S> for BeaconBlockHeader {
    /// Checks the block's place in the chain, and records its header.
    ///
    /// The recorded state root stays empty here.
    /// The next slot fills it once the post-state root is known.
    ///
    /// No fork changed this step.
    /// See `process_block_header` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = processor.state.beacon();
        let state_slot = state.slot();
        if self.slot != state_slot {
            return Err(BlockError::SlotMismatch {
                block: self.slot,
                state: state_slot,
            });
        }
        let latest_slot = state.latest_block_header().slot;
        if self.slot <= latest_slot {
            return Err(BlockError::NotNewerThanParent {
                block: self.slot,
                latest: latest_slot,
            });
        }
        let expected = processor.proposer()?;
        if self.proposer_index != expected {
            return Err(BlockError::WrongProposer {
                claimed: self.proposer_index,
                expected,
            });
        }
        let parent = processor
            .state
            .beacon()
            .latest_block_header()
            .hash_tree_root();
        if self.parent_root != parent {
            return Err(BlockError::ParentMismatch {
                claimed: self.parent_root,
                expected: parent,
            });
        }

        let state = &mut *processor.state.beacon;
        *state.latest_block_header_mut() = Self {
            state_root: Root::ZERO,
            ..self.clone()
        };

        let validators = state.validators();
        let proposer =
            validators
                .get(self.proposer_index.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index: self.proposer_index,
                    registry_size: validators.len(),
                })?;
        if proposer.slashed {
            return Err(BlockError::ProposerSlashed(self.proposer_index));
        }
        Ok(())
    }
}
