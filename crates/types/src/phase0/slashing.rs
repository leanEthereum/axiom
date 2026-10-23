//! Evidence of slashable behaviour.

use std::collections::HashSet;

use axiom_ssz::{CapacityError, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{
    Preset, ValidatorIndex,
    phase0::{IndexedAttestation, SignedBeaconBlockHeader},
    vote::ConflictingVotes,
};

/// Two distinct signed headers from one proposer for one slot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposerSlashing {
    /// The first header.
    pub signed_header_1: SignedBeaconBlockHeader,

    /// The conflicting second header.
    pub signed_header_2: SignedBeaconBlockHeader,
}

impl Container for ProposerSlashing {
    const FIELDS: &'static [Option<usize>] = &[
        SignedBeaconBlockHeader::FIXED_SIZE,
        SignedBeaconBlockHeader::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.signed_header_1);
        visitor.field(&self.signed_header_2);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            signed_header_1: fields.field()?,
            signed_header_2: fields.field()?,
        })
    }
}

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
    /// The slashing two conflicting votes make in this container.
    ///
    /// # Errors
    ///
    /// Fails when a vote has more signers than one committee holds.
    pub fn from_votes(votes: &ConflictingVotes) -> Result<Self, CapacityError> {
        Ok(Self {
            attestation_1: IndexedAttestation::from_vote(&votes.first)?,
            attestation_2: IndexedAttestation::from_vote(&votes.second)?,
        })
    }

    /// The two votes reduced to the fields every fork shares.
    #[must_use]
    pub fn conflicting_votes(&self) -> ConflictingVotes {
        ConflictingVotes {
            first: self.attestation_1.indexed_vote(),
            second: self.attestation_2.indexed_vote(),
        }
    }

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
