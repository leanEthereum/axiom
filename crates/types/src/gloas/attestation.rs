//! Attestations of Gloas, whose participant lists are unbounded.
//!
//! See EIP-7688.

use std::collections::HashSet;

use axiom_ssz::{
    Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, ProgressiveBitList,
    ProgressiveList, Ssz,
};

use crate::{
    BlsSignature, CommitteeIndex, Preset, ValidatorIndex,
    gloas::{AttestationData, CommitteeBits},
};

/// Participation bits of every committee in an attestation, concatenated in committee order.
pub type AggregationBits = ProgressiveBitList;

/// Indices of the validators behind an attestation, sorted and unique.
pub type AttestingIndices = ProgressiveList<ValidatorIndex>;

/// An aggregate of identical votes from one or more committees.
///
/// See EIP-7549 for aggregation across committees.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attestation<P: Preset> {
    /// Which committee members signed, across all aggregated committees.
    pub aggregation_bits: AggregationBits,

    /// The vote.
    pub data: AttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,

    /// Which committees of the slot are aggregated.
    pub committee_bits: CommitteeBits<P>,
}

impl<P: Preset> Container for Attestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        AggregationBits::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
        <CommitteeBits<P>>::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 4]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.aggregation_bits);
        visitor.field(&self.data);
        visitor.field(&self.signature);
        visitor.field(&self.committee_bits);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            aggregation_bits: fields.field()?,
            data: fields.field()?,
            signature: fields.field()?,
            committee_bits: fields.field()?,
        })
    }
}

impl<P: Preset> Attestation<P> {
    /// Indices of the committees this attestation aggregates, in increasing order.
    pub fn committee_indices(&self) -> impl Iterator<Item = CommitteeIndex> + '_ {
        self.committee_bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit)
            .map(|(index, _)| CommitteeIndex::from(index))
    }
}

/// An attestation with its participants listed by validator index.
///
/// Slashing evidence uses this form, since it does not depend on committee shuffling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexedAttestation {
    /// Participants, sorted and unique.
    pub attesting_indices: AttestingIndices,

    /// The vote.
    pub data: AttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,
}

impl Container for IndexedAttestation {
    const FIELDS: &'static [Option<usize>] = &[
        AttestingIndices::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 3]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.attesting_indices);
        visitor.field(&self.data);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attesting_indices: fields.field()?,
            data: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// Two attestations that violate a Casper FFG commandment.
///
/// They either vote for two targets in one epoch, or one surrounds the other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttesterSlashing {
    /// The first attestation.
    pub attestation_1: IndexedAttestation,

    /// The conflicting second attestation.
    pub attestation_2: IndexedAttestation,
}

impl Container for AttesterSlashing {
    const FIELDS: &'static [Option<usize>] = &[
        IndexedAttestation::FIXED_SIZE,
        IndexedAttestation::FIXED_SIZE,
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

impl AttesterSlashing {
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
