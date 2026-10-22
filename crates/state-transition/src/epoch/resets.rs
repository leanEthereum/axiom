//! End-of-epoch rotations of the state's ring buffers and per-epoch fields.

use std::mem;

use axiom_ssz::{List, Ssz};
use axiom_types::{Gwei, HistoricalSummary, ParticipationFlags, Preset};

use super::EpochProcessor;
use crate::StateError;

impl<P: Preset> EpochProcessor<'_, P> {
    /// Clears the eth1 data votes when a voting period ends.
    pub fn process_eth1_data_reset(&mut self) {
        if (self.current_epoch + 1)
            .0
            .is_multiple_of(P::EPOCHS_PER_ETH1_VOTING_PERIOD)
        {
            self.state.beacon.eth1_data_votes = List::new();
        }
    }

    /// Clears the slashings slot the next epoch will accumulate into.
    pub fn process_slashings_reset(&mut self) {
        let next = (self.current_epoch + 1) % P::EPOCHS_PER_SLASHINGS_VECTOR;
        self.state.beacon.slashings[next as usize] = Gwei::ZERO;
    }

    /// Seeds the next epoch's randao mix with the current one.
    pub fn process_randao_mixes_reset(&mut self) {
        let state = &mut self.state.beacon;
        let next = (self.current_epoch + 1) % P::EPOCHS_PER_HISTORICAL_VECTOR;
        state.randao_mixes[next as usize] = state.randao_mix(self.current_epoch);
    }

    /// Appends a summary of the root ring buffers each time they wrap around.
    ///
    /// See `process_historical_summaries_update` in the Capella beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the summary list is full.
    pub fn process_historical_summaries_update(&mut self) -> Result<(), StateError> {
        let period = P::SLOTS_PER_HISTORICAL_ROOT / P::SLOTS_PER_EPOCH;
        if (self.current_epoch + 1).0.is_multiple_of(period) {
            let state = &mut self.state.beacon;
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
    /// # Errors
    ///
    /// Fails when the registry exceeds its limit, which cannot happen.
    pub fn process_participation_flag_updates(&mut self) -> Result<(), StateError> {
        let state = &mut self.state.beacon;
        let fresh = vec![ParticipationFlags::default(); state.validators.len()];
        state.previous_epoch_participation = mem::replace(
            &mut state.current_epoch_participation,
            fresh.try_into().map_err(|_| StateError::ListFull)?,
        );
        Ok(())
    }
}
