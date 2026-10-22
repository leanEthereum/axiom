//! Attester slashings of Electra, whose attestations span a whole slot.

use std::collections::HashSet;

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{Preset, ValidatorIndex, electra::IndexedAttestation};

/// Two attestations that violate a Casper FFG commandment.
///
/// They either vote for two targets in one epoch, or one surrounds the other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttesterSlashing<P: Preset> {
    /// The first attestation.
    pub attestation_1: IndexedAttestation<P>,

    /// The conflicting second attestation.
    pub attestation_2: IndexedAttestation<P>,
}

impl<P: Preset> Container for AttesterSlashing<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <IndexedAttestation<P>>::FIXED_SIZE,
        <IndexedAttestation<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.attestation_1);
        visitor.field(&self.attestation_2);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attestation_1: fields.field()?,
            attestation_2: fields.field()?,
        })
    }
}

impl<P: Preset> AttesterSlashing<P> {
    /// Validators that signed both attestations, in the first attestation's order.
    ///
    /// Only these validators can be slashed by the evidence.
    /// See `process_attester_slashing` in the phase0 beacon chain spec.
    #[must_use]
    pub fn common_signers(&self) -> Vec<ValidatorIndex> {
        let second: HashSet<ValidatorIndex> = self
            .attestation_2
            .attesting_indices
            .iter()
            .copied()
            .collect();
        self.attestation_1
            .attesting_indices
            .iter()
            .copied()
            .filter(|index| second.contains(index))
            .collect()
    }
}
