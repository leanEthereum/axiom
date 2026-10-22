//! Attester slashings: punishing validators that cast slashable votes.

use axiom_types::{
    BlsSignature, Preset, ValidatorIndex, electra, gloas, phase0, phase0::AttestationData,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

/// One side of an attester slashing: an indexed vote and its signature.
#[derive(Clone, Copy, Debug)]
struct Vote<'a> {
    /// The signers, sorted.
    indices: &'a [ValidatorIndex],
    /// What they voted for.
    data: &'a AttestationData,
    /// Their aggregate signature.
    signature: &'a BlsSignature,
}

/// Two conflicting votes, and the validators that signed both.
///
/// Electra and Gloas widened the index lists, but the rule never changed.
/// See `process_attester_slashing` in the phase0 beacon chain spec.
#[derive(Debug)]
struct ConflictingVotes<'a> {
    /// The first vote.
    first: Vote<'a>,
    /// The second vote.
    second: Vote<'a>,
    /// Validators in both votes, ascending.
    common: Vec<ValidatorIndex>,
}

impl ConflictingVotes<'_> {
    /// Slashes every slashable validator that signed both votes.
    fn apply<S: Fork>(self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        if !self.first.data.is_slashable_with(self.second.data) {
            return Err(BlockError::AttestationsNotSlashable {
                first_target: self.first.data.target.epoch,
                second_target: self.second.data.target.epoch,
            });
        }
        for vote in [self.first, self.second] {
            processor.verify_indexed_attestation(vote.indices, vote.data, vote.signature)?;
        }

        // Both lists are verified sorted, so the common signers come out in ascending order.
        let epoch = processor.state.beacon().current_epoch();
        let mut slashed_any = false;
        for index in &self.common {
            let validators = processor.state.beacon().validators();
            let validator =
                validators
                    .get(index.as_usize())
                    .ok_or(StateError::UnknownValidator {
                        index: *index,
                        registry_size: validators.len(),
                    })?;
            if validator.is_slashable_at(epoch) {
                processor.registry().slash(*index, None)?;
                slashed_any = true;
            }
        }
        if !slashed_any {
            return Err(BlockError::NoValidatorSlashed {
                common: self.common.len(),
            });
        }
        processor
            .state
            .caches
            .proposer_ledger
            .settle_attester_slashing();
        Ok(())
    }
}

impl<S: Fork> Operation<S> for phase0::AttesterSlashing<S::Preset> {
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        ConflictingVotes {
            first: Vote {
                indices: &self.attestation_1.attesting_indices,
                data: &self.attestation_1.data,
                signature: &self.attestation_1.signature,
            },
            second: Vote {
                indices: &self.attestation_2.attesting_indices,
                data: &self.attestation_2.data,
                signature: &self.attestation_2.signature,
            },
            common: self.common_signers(),
        }
        .apply(processor)
    }
}

impl<S: Fork> Operation<S> for electra::AttesterSlashing<S::Preset> {
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        ConflictingVotes {
            first: Vote {
                indices: &self.attestation_1.attesting_indices,
                data: &self.attestation_1.data,
                signature: &self.attestation_1.signature,
            },
            second: Vote {
                indices: &self.attestation_2.attesting_indices,
                data: &self.attestation_2.data,
                signature: &self.attestation_2.signature,
            },
            common: self.common_signers(),
        }
        .apply(processor)
    }
}

impl<S: Fork> Operation<S> for gloas::AttesterSlashing {
    /// Gloas lists are progressive, so each vote's signers are bounded here instead, see EIP-7688.
    ///
    /// Threshold: the committee size limit times the committees in a slot.
    /// See `is_valid_indexed_attestation` in the Gloas beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let limit = S::Preset::MAX_VALIDATORS_PER_COMMITTEE * S::Preset::MAX_COMMITTEES_PER_SLOT;
        for vote in [&self.attestation_1, &self.attestation_2] {
            let count = vote.attesting_indices.len();
            if count as u64 > limit {
                return Err(BlockError::TooManyAttestingIndices { count, limit });
            }
        }
        ConflictingVotes {
            first: Vote {
                indices: &self.attestation_1.attesting_indices,
                data: &self.attestation_1.data,
                signature: &self.attestation_1.signature,
            },
            second: Vote {
                indices: &self.attestation_2.attesting_indices,
                data: &self.attestation_2.data,
                signature: &self.attestation_2.signature,
            },
            common: self.common_signers(),
        }
        .apply(processor)
    }
}
