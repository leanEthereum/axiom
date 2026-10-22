//! Deposits that register validators with participation flags and an inactivity score.

use axiom_types::{accessors::ParticipationState, phase0::Deposit};

use crate::{
    BlockError, BlockProcessor, Fork, Operation, StateError, phase0::block::ContractDeposit,
};

/// A deposit from the deposit contract, registered by Altair's rule.
///
/// The proof and top-up rules are phase0's.
/// A new validator also gets empty flags for both epochs and a zero inactivity score.
/// Bellatrix, Capella, and Deneb kept this rule, and Electra queued deposits instead.
/// See `add_validator_to_registry` in the Altair beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct ParticipantDeposit<'a>(pub &'a Deposit);

impl<S: Fork + ParticipationState> Operation<S> for ParticipantDeposit<'_> {
    /// Applies a deposit, registering a new validator in every per-validator list.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let Some(validator) = ContractDeposit(self.0).admit(processor)? else {
            return Ok(());
        };
        let state = &mut *processor.state.beacon;
        state
            .push_validator(validator, self.0.data.amount)
            .map_err(|source| StateError::Capacity {
                list: "validators",
                source,
            })?;
        state
            .push_participant()
            .map_err(|source| StateError::Capacity {
                list: "participation",
                source,
            })?;
        Ok(())
    }
}
