//! The per-slot caching of state and block roots.

use axiom_ssz::Ssz;
use axiom_types::{Preset, Root, accessors::CoreState};

/// The roots of the slot that just ended, about to be cached in the state.
///
/// The latest header's state root is left empty while its block is processed.
/// It is filled here, one slot later, once the post-state is known.
///
/// See `process_slot` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotRoots {
    /// Position of the slot in the ring buffers.
    index: usize,
    /// Root of the state at the end of the slot.
    state_root: Root,
}

impl SlotRoots {
    /// The roots of a state's slot.
    #[must_use]
    pub fn of<S: CoreState + ?Sized>(state: &S) -> Self {
        Self {
            index: (state.slot() % S::Preset::SLOTS_PER_HISTORICAL_ROOT) as usize,
            state_root: state.state_root(),
        }
    }

    /// Writes the state root, completes the latest header, and writes its block root.
    pub fn record<S: CoreState + ?Sized>(self, state: &mut S) {
        state.state_roots_mut()[self.index] = self.state_root;
        let header = state.latest_block_header_mut();
        if header.state_root == Root::ZERO {
            header.state_root = self.state_root;
        }
        let block_root = header.hash_tree_root();
        state.block_roots_mut()[self.index] = block_root;
    }
}
