//! Historical summaries, which replaced the historical roots accumulator.

use axiom_ssz::Ssz;
use axiom_types::{Epoch, Preset, accessors::WithdrawalState, capella::HistoricalSummary};

use crate::StateError;

/// The summary appended each time the root ring buffers wrap around.
///
/// See `process_historical_summaries_update` in the Capella beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalSummaryUpdate {
    /// The epoch that begins.
    next: Epoch,
}

impl HistoricalSummaryUpdate {
    /// The update at the end of an epoch.
    #[must_use]
    pub fn new(current: Epoch) -> Self {
        Self { next: current + 1 }
    }

    /// Appends a summary of the block and state roots when a full period ends.
    ///
    /// # Errors
    ///
    /// Fails when the summary list is full.
    pub fn apply<S: WithdrawalState + ?Sized>(self, state: &mut S) -> Result<(), StateError> {
        let period = S::Preset::SLOTS_PER_HISTORICAL_ROOT / S::Preset::SLOTS_PER_EPOCH;
        if self.next.0.is_multiple_of(period) {
            let summary = HistoricalSummary {
                block_summary_root: state.block_roots().hash_tree_root(),
                state_summary_root: state.state_roots().hash_tree_root(),
            };
            state
                .historical_summaries_mut()
                .push(summary)
                .map_err(|source| StateError::Capacity {
                    list: "historical summaries",
                    source,
                })?;
        }
        Ok(())
    }
}
