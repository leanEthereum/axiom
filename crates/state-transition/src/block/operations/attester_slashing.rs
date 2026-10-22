//! Attester slashings: punishing validators that cast slashable votes.

use axiom_types::{Preset, fulu::AttesterSlashing};

use crate::{BlockError, BlockProcessor, Operation, StateError};

impl<P: Preset> Operation<P> for AttesterSlashing<P> {
    /// Slashes every slashable validator that signed both of two conflicting votes.
    ///
    /// See `process_attester_slashing` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        if !self
            .attestation_1
            .data
            .is_slashable_with(&self.attestation_2.data)
        {
            return Err(BlockError::AttestationsNotSlashable {
                first_target: self.attestation_1.data.target.epoch,
                second_target: self.attestation_2.data.target.epoch,
            });
        }
        processor.verify_indexed_attestation(&self.attestation_1)?;
        processor.verify_indexed_attestation(&self.attestation_2)?;

        // Both lists are verified sorted, so the common signers come out in ascending order.
        let epoch = processor.state.beacon.current_epoch();
        let mut slashed_any = false;
        let mut common = 0;
        for index in self.common_signers() {
            common += 1;
            let validators = &processor.state.beacon.validators;
            let validator =
                validators
                    .get(index.as_usize())
                    .ok_or(StateError::UnknownValidator {
                        index,
                        registry_size: validators.len(),
                    })?;
            if validator.is_slashable_at(epoch) {
                processor.registry().slash(index, None)?;
                slashed_any = true;
            }
        }
        if !slashed_any {
            return Err(BlockError::NoValidatorSlashed { common });
        }
        Ok(())
    }
}
