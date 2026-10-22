//! The historical roots accumulator, extended each time the root ring buffers wrap around.

use axiom_ssz::Ssz;
use axiom_types::{Epoch, Preset, Root, accessors::CoreState};

use crate::StateError;

/// The root appended when a full period of block and state roots ends.
///
/// The appended root commits to the block roots and the state roots of the period together.
/// Capella froze this list and appends historical summaries instead.
/// See `process_historical_roots_update` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalRootsUpdate {
    /// The epoch that begins.
    next: Epoch,
}

impl HistoricalRootsUpdate {
    /// The update at the end of an epoch.
    #[must_use]
    pub fn new(current: Epoch) -> Self {
        Self { next: current + 1 }
    }

    /// Appends the root of the period's roots when a full period ends.
    ///
    /// # Errors
    ///
    /// Fails when the historical roots list is full.
    pub fn apply<S: CoreState + ?Sized>(self, state: &mut S) -> Result<(), StateError> {
        let period = S::Preset::SLOTS_PER_HISTORICAL_ROOT / S::Preset::SLOTS_PER_EPOCH;
        if !self.next.0.is_multiple_of(period) {
            return Ok(());
        }
        // The batch is a container of two fields, so its root hashes the two field roots.
        let batch_root = Root::hash_pair(
            &state.block_roots().hash_tree_root(),
            &state.state_roots().hash_tree_root(),
        );
        state
            .historical_roots_mut()
            .push(batch_root)
            .map_err(|source| StateError::Capacity {
                list: "historical roots",
                source,
            })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, altair, phase0::HistoricalBatch};

    use super::*;

    #[test]
    fn the_appended_root_is_the_batch_root() {
        // Fixture state: Altair with distinct block and state roots.
        // Minimal preset: 64 slots per historical root over 8 slots per epoch is 8 epochs.
        let mut state = altair::BeaconState::<Minimal>::default();
        state.block_roots[0] = Root([1; 32]);
        state.state_roots[5] = Root([2; 32]);

        // Epoch 6 ends into epoch 7, which starts no period, so nothing is appended.
        HistoricalRootsUpdate::new(Epoch(6))
            .apply(&mut state)
            .unwrap();
        assert!(state.historical_roots.is_empty());

        // Epoch 7 ends into epoch 8, which starts one, so the batch root is appended.
        HistoricalRootsUpdate::new(Epoch(7))
            .apply(&mut state)
            .unwrap();
        let batch = HistoricalBatch::<Minimal> {
            block_roots: state.block_roots.clone(),
            state_roots: state.state_roots.clone(),
        };
        assert_eq!(state.historical_roots.as_slice(), &[batch.hash_tree_root()]);
    }
}
