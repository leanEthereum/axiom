//! Attester slashings: punishing validators that cast slashable votes.

use std::cmp::Ordering;

use axiom_bls::PublicKey;
use axiom_types::{
    AttesterSlashing, IndexedAttestation, Preset, SigningData, ValidatorIndex,
    constants::DOMAIN_BEACON_ATTESTER,
};

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
            return Err(BlockError::AttestationsNotSlashable);
        }
        processor.verify_indexed_attestation(&self.attestation_1)?;
        processor.verify_indexed_attestation(&self.attestation_2)?;

        // Both lists are sorted, so a merge walk yields the sorted intersection.
        let both = sorted_intersection(&self.attestation_1, &self.attestation_2);

        let epoch = processor.state.beacon.current_epoch();
        let total_active_balance = processor.total_active_balance;
        let mut slashed_any = false;
        for index in both {
            let validator = processor
                .state
                .beacon
                .validators
                .get(index.as_usize())
                .ok_or(StateError::UnknownValidator(index))?;
            if validator.is_slashable_at(epoch) {
                processor.state.slash_validator(
                    processor.config,
                    index,
                    None,
                    total_active_balance,
                )?;
                slashed_any = true;
            }
        }
        if !slashed_any {
            return Err(BlockError::NoValidatorSlashed);
        }
        Ok(())
    }
}

impl<P: Preset> BlockProcessor<'_, P> {
    /// Checks an indexed attestation: sorted unique signers, and a valid aggregate signature.
    ///
    /// See `is_valid_indexed_attestation` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the indices are empty, unsorted, repeated, or unknown, or the signature is malformed.
    pub fn verify_indexed_attestation(
        &mut self,
        attestation: &IndexedAttestation<P>,
    ) -> Result<(), BlockError> {
        let indices = &attestation.attesting_indices;
        let strictly_increasing = indices.windows(2).all(|pair| pair[0] < pair[1]);
        if indices.is_empty() || !strictly_increasing {
            return Err(BlockError::InvalidAttestingIndices);
        }
        // Every index must name a validator, signatures checked or not.
        let registry_size = self.state.beacon.validators.len() as u64;
        if let Some(unknown) = indices.iter().find(|index| index.0 >= registry_size) {
            return Err(StateError::UnknownValidator(*unknown).into());
        }

        if !self.signatures.is_enabled() {
            return Ok(());
        }
        let keys = indices
            .iter()
            .map(|index| self.state.public_key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        let key = PublicKey::aggregate(&keys).map_err(|_| BlockError::InvalidSignature)?;
        let domain = self
            .state
            .beacon
            .domain(DOMAIN_BEACON_ATTESTER, attestation.data.target.epoch);
        let root = SigningData::signing_root(&attestation.data, domain);
        self.verify_root(key, root, &attestation.signature)
    }
}

/// Sorted intersection of the signers of two indexed attestations.
fn sorted_intersection<P: Preset>(
    first: &IndexedAttestation<P>,
    second: &IndexedAttestation<P>,
) -> Vec<ValidatorIndex> {
    let (mut left, mut right) = (
        first.attesting_indices.iter().peekable(),
        second.attesting_indices.iter().peekable(),
    );
    let mut both = Vec::new();
    while let (Some(a), Some(b)) = (left.peek(), right.peek()) {
        match a.cmp(b) {
            Ordering::Less => {
                left.next();
            }
            Ordering::Greater => {
                right.next();
            }
            Ordering::Equal => {
                both.push(**a);
                left.next();
                right.next();
            }
        }
    }
    both
}
