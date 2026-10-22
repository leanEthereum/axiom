//! The eth1 data step: voting on the deposit contract snapshot.

use axiom_types::{BeaconBlockBody, Preset};

use super::BlockProcessor;
use crate::{BlockError, StateError};

impl<P: Preset> BlockProcessor<'_, P> {
    /// Records the proposer's eth1 data vote, adopting it once it has a majority of the period.
    ///
    /// Threshold: more than half of the 64 * 32 slots of the voting period.
    ///
    /// See `process_eth1_data` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the vote list is full, which a valid chain never reaches.
    pub fn process_eth1_data(&mut self, body: &BeaconBlockBody<P>) -> Result<(), BlockError> {
        let state = &mut self.state.beacon;
        state
            .eth1_data_votes
            .push(body.eth1_data.clone())
            .map_err(|_| StateError::ListFull)?;
        let votes = state
            .eth1_data_votes
            .iter()
            .filter(|vote| **vote == body.eth1_data)
            .count() as u64;
        if votes * 2 > P::EPOCHS_PER_ETH1_VOTING_PERIOD * P::SLOTS_PER_EPOCH {
            state.eth1_data = body.eth1_data.clone();
        }
        Ok(())
    }
}
