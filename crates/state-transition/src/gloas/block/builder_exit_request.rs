//! Builder exit requests: a builder leaving the registry, asked from its execution address.

use axiom_types::{BuilderIndex, Gwei, accessors::BuilderState, gloas::BuilderExitRequest};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork + BuilderState> Operation<S> for BuilderExitRequest {
    /// Starts the exit of an active builder that owes nothing, at its own address's request.
    ///
    /// A request that breaks a rule is ignored rather than invalidating the block.
    /// The execution layer cannot know the beacon state, so it relays every request it sees.
    ///
    /// The builder's balance becomes withdrawable after the builder withdrawability delay.
    /// See EIP-8282, `process_builder_exit_request`, and `initiate_builder_exit` in the Gloas spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = &mut *processor.state.beacon;
        let Some(position) = state
            .builders()
            .iter()
            .position(|builder| builder.pubkey == self.pubkey)
        else {
            return Ok(());
        };
        let index = BuilderIndex::from(position);
        let builder = &state.builders()[position];
        if !builder.is_active(state.finalized_checkpoint().epoch)
            || builder.execution_address != self.source_address
            || state.pending_balance_to_withdraw_for_builder(index) != Gwei::ZERO
        {
            return Ok(());
        }
        let withdrawable = state
            .current_epoch()
            .checked_add(processor.config.min_builder_withdrawability_delay)
            .ok_or(StateError::Overflow {
                quantity: "builder withdrawable epoch",
            })?;
        state.builders_mut()[position].withdrawable_epoch = withdrawable;
        Ok(())
    }
}
