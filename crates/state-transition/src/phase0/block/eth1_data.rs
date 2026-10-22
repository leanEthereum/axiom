//! The eth1 data step: voting on the deposit contract snapshot.

use axiom_types::{Preset, phase0::Eth1Data};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork> Operation<S> for Eth1Data {
    /// Records the proposer's eth1 data vote, adopting it once it has a majority of the period.
    ///
    /// Threshold: more than half of the 64 * 32 slots of the voting period.
    ///
    /// No fork changed this step.
    /// See `process_eth1_data` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = &mut *processor.state.beacon;
        let votes = state.eth1_data_votes_mut();
        votes
            .push(self.clone())
            .map_err(|source| StateError::Capacity {
                list: "eth1 data votes",
                source,
            })?;
        let count = votes.iter().filter(|vote| *vote == self).count() as u64;
        if count * 2 > S::Preset::EPOCHS_PER_ETH1_VOTING_PERIOD * S::Preset::SLOTS_PER_EPOCH {
            *state.eth1_data_mut() = self.clone();
        }
        Ok(())
    }
}
