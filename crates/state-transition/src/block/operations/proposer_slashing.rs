//! Proposer slashings: punishing a proposer that signed two blocks for one slot.

use axiom_types::{Preset, constants::DOMAIN_BEACON_PROPOSER, fulu::ProposerSlashing};

use crate::{BlockError, BlockProcessor, Operation, StateError};

impl<P: Preset> Operation<P> for ProposerSlashing {
    /// Slashes the proposer of two distinct, signed headers for the same slot.
    ///
    /// See `process_proposer_slashing` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let header_1 = &self.signed_header_1.message;
        let header_2 = &self.signed_header_2.message;
        let proposer = header_1.proposer_index;
        let invalid = |reason| BlockError::InvalidProposerSlashing { proposer, reason };
        if header_1.slot != header_2.slot {
            return Err(invalid("headers are from different slots"));
        }
        if header_1.proposer_index != header_2.proposer_index {
            return Err(invalid("headers name different proposers"));
        }
        if header_1 == header_2 {
            return Err(invalid("headers are equal"));
        }

        let state = &processor.state.beacon;
        let validator =
            state
                .validators
                .get(proposer.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index: proposer,
                    registry_size: state.validators.len(),
                })?;
        if !validator.is_slashable_at(state.current_epoch()) {
            return Err(invalid("proposer is not slashable"));
        }

        for signed in [&self.signed_header_1, &self.signed_header_2] {
            let domain = processor
                .state
                .beacon
                .domain(DOMAIN_BEACON_PROPOSER, signed.message.slot.epoch::<P>());
            processor.verify_signature(proposer, &signed.message, domain, &signed.signature)?;
        }

        processor.registry().slash(proposer, None)?;
        Ok(())
    }
}
