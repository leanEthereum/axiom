//! End-of-epoch rotations of the state's ring buffers and per-epoch fields.

use std::mem;

use axiom_ssz::{List, Ssz};
use axiom_types::{BeaconState, Epoch, Gwei, HistoricalSummary, ParticipationFlags, Preset};

use crate::StateError;

/// The passage from the ending epoch to the next one.
///
/// Ring buffers indexed by epoch advance one slot, and per-epoch fields restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rollover {
    /// The epoch that is ending.
    current: Epoch,
    /// The epoch that begins.
    next: Epoch,
}

impl Rollover {
    /// The passage out of an epoch.
    pub(super) fn new(current: Epoch) -> Self {
        Self {
            current,
            next: current + 1,
        }
    }

    /// Clears the eth1 data votes when a voting period ends.
    ///
    /// See `process_eth1_data_reset` in the phase0 beacon chain spec.
    pub(super) fn reset_eth1_data<P: Preset>(self, state: &mut BeaconState<P>) {
        if self.next.0.is_multiple_of(P::EPOCHS_PER_ETH1_VOTING_PERIOD) {
            state.eth1_data_votes = List::new();
        }
    }

    /// Clears the slashings slot the next epoch will accumulate into.
    ///
    /// See `process_slashings_reset` in the phase0 beacon chain spec.
    pub(super) fn reset_slashings<P: Preset>(self, state: &mut BeaconState<P>) {
        let next = self.next % P::EPOCHS_PER_SLASHINGS_VECTOR;
        state.slashings[next as usize] = Gwei::ZERO;
    }

    /// Seeds the next epoch's randao mix with the current one.
    ///
    /// See `process_randao_mixes_reset` in the phase0 beacon chain spec.
    pub(super) fn reset_randao_mix<P: Preset>(self, state: &mut BeaconState<P>) {
        let next = self.next % P::EPOCHS_PER_HISTORICAL_VECTOR;
        state.randao_mixes[next as usize] = state.randao_mix(self.current);
    }

    /// Appends a summary of the root ring buffers each time they wrap around.
    ///
    /// See `process_historical_summaries_update` in the Capella beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the summary list is full.
    pub(super) fn update_historical_summaries<P: Preset>(
        self,
        state: &mut BeaconState<P>,
    ) -> Result<(), StateError> {
        let period = P::SLOTS_PER_HISTORICAL_ROOT / P::SLOTS_PER_EPOCH;
        if self.next.0.is_multiple_of(period) {
            let summary = HistoricalSummary {
                block_summary_root: state.block_roots.hash_tree_root(),
                state_summary_root: state.state_roots.hash_tree_root(),
            };
            state
                .historical_summaries
                .push(summary)
                .map_err(|_| StateError::ListFull)?;
        }
        Ok(())
    }

    /// Rotates the current participation flags into the previous epoch.
    ///
    /// See `process_participation_flag_updates` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the registry exceeds its limit, which cannot happen.
    pub(super) fn rotate_participation<P: Preset>(
        state: &mut BeaconState<P>,
    ) -> Result<(), StateError> {
        let fresh = vec![ParticipationFlags::default(); state.validators.len()];
        state.previous_epoch_participation = mem::replace(
            &mut state.current_epoch_participation,
            fresh.try_into().map_err(|_| StateError::ListFull)?,
        );
        Ok(())
    }
}
