//! The eth1 data step: voting on the deposit contract snapshot.

use axiom_types::{Preset, fulu::Eth1Data};

use super::{BlockProcessor, Operation};
use crate::{BlockError, StateError};

impl<P: Preset> Operation<P> for Eth1Data {
    /// Records the proposer's eth1 data vote, adopting it once it has a majority of the period.
    ///
    /// Threshold: more than half of the 64 * 32 slots of the voting period.
    ///
    /// See `process_eth1_data` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let state = &mut processor.state.beacon;
        state
            .eth1_data_votes
            .push(self.clone())
            .map_err(|source| StateError::Capacity {
                list: "eth1 data votes",
                source,
            })?;
        let votes = state
            .eth1_data_votes
            .iter()
            .filter(|vote| *vote == self)
            .count() as u64;
        if votes * 2 > P::EPOCHS_PER_ETH1_VOTING_PERIOD * P::SLOTS_PER_EPOCH {
            state.eth1_data = self.clone();
        }
        Ok(())
    }
}
