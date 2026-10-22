//! A block paired with its immediate post-state, the input a full node derives data from.

use axiom_ssz::{GeneralizedIndex, Root, Ssz};
use axiom_types::{
    Bytes32, Preset,
    combined::{BeaconState, SignedBeaconBlock},
};

use crate::{Layout, LightClientError, branch::Branch};

/// A block and the state right after it, checked to belong together.
///
/// # Overview
///
/// Light client data proves fields of a state against the state root in a block header.
/// The state must therefore be the block's own post-state, before any empty slot.
/// The check runs once here, so creating data from the pair cannot skip it.
///
/// See the assertions of `create_light_client_bootstrap` in the Altair light client full node spec.
#[derive(Clone, Copy, Debug)]
pub struct PostState<'a, P: Preset> {
    /// The post-state.
    state: &'a BeaconState<P>,
    /// The block.
    block: &'a SignedBeaconBlock<P>,
    /// The block's root.
    root: Root,
}

impl<'a, P: Preset> PostState<'a, P> {
    /// Pairs a state with the block it follows.
    ///
    /// # Errors
    ///
    /// Fails when the state has processed an empty slot, or follows another block.
    pub fn new(
        state: &'a BeaconState<P>,
        block: &'a SignedBeaconBlock<P>,
    ) -> Result<Self, LightClientError> {
        let core = state.as_core();
        let latest = core.latest_block_header();
        if core.slot() != latest.slot {
            return Err(LightClientError::StateAdvanced {
                state: core.slot(),
                block: latest.slot,
            });
        }
        // The latest header keeps a zero state root until the next slot fills it in.
        let mut header = latest.clone();
        header.state_root = state.hash_tree_root();
        let root = header.hash_tree_root();
        let block_root = block.block_root();
        if root != block_root {
            return Err(LightClientError::NotPostState {
                state: root,
                block: block_root,
            });
        }
        Ok(Self { state, block, root })
    }

    /// The post-state.
    #[must_use]
    pub const fn state(&self) -> &'a BeaconState<P> {
        self.state
    }

    /// The block.
    #[must_use]
    pub const fn block(&self) -> &'a SignedBeaconBlock<P> {
        self.block
    }

    /// The block's root.
    #[must_use]
    pub const fn root(&self) -> Root {
        self.root
    }

    /// Where the state keeps what light client data proves, by the state's own fork.
    ///
    /// The spec reads the fork from the state's slot; the state's own shape is the same answer.
    pub(crate) fn layout(&self) -> Layout {
        Layout::of(self.state.as_core().fork_name())
    }

    /// The branch proving the state's node at a generalized index.
    pub(crate) fn prove(&self, gindex: GeneralizedIndex) -> Result<Vec<Bytes32>, LightClientError> {
        self.state
            .prove(gindex)
            .map(|(_, proof)| Branch::nodes_of(&proof))
            .ok_or_else(|| LightClientError::MissingNode {
                fork: self.state.as_core().fork_name(),
                gindex: gindex.get(),
            })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ForkName, Slot, altair::SyncAggregate, phase0::Checkpoint};

    use super::*;
    use crate::fixture::Chain;

    #[test]
    fn a_state_pairs_only_with_its_own_block_before_any_empty_slot() {
        // Fixture state: an Altair chain with a block at slot 8 and one at slot 9.
        let chain = Chain::new(ForkName::Altair);
        let (state, block) = chain.block(
            Slot(8),
            Root::ZERO,
            Checkpoint::default(),
            SyncAggregate::default(),
        );
        let (_, other) = chain.block(
            Slot(9),
            Root::ZERO,
            Checkpoint::default(),
            SyncAggregate::default(),
        );
        assert_eq!(
            PostState::new(&state, &block).unwrap().root(),
            block.block_root()
        );

        // Mutation: the slot 9 block, which the slot 8 state does not follow.
        let mut header = state.as_core().latest_block_header().clone();
        header.state_root = state.hash_tree_root();
        assert_eq!(
            PostState::new(&state, &other).unwrap_err(),
            LightClientError::NotPostState {
                state: header.hash_tree_root(),
                block: other.block_root(),
            }
        );

        // Mutation: the state processes the empty slot 9, so it no longer sits at its block.
        let mut advanced = state;
        *advanced.as_core_mut().slot_mut() = Slot(9);
        assert_eq!(
            PostState::new(&advanced, &block).unwrap_err(),
            LightClientError::StateAdvanced {
                state: Slot(9),
                block: Slot(8),
            }
        );
    }
}
