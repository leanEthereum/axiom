//! Attestations of Electra, which aggregate across the committees of a slot.

use axiom_ssz::{
    BitList, BitVector, CapacityError, Container, DecodeError, FieldDecoder, FieldVisitor, List,
    Ssz,
};

use crate::{
    BlsSignature, CommitteeIndex, Preset, ValidatorIndex,
    electra::AttestationData,
    vote::{CommitteeVote, IndexedVote, PayloadClaim},
};

/// Participation bits of every committee in an attestation, concatenated in committee order.
pub type AggregationBits<P> = BitList<<P as Preset>::MaxValidatorsPerSlot>;

/// The committees an attestation aggregates.
pub type CommitteeBits<P> = BitVector<<P as Preset>::MaxCommitteesPerSlot>;

/// Indices of the validators behind an attestation, sorted and unique.
pub type AttestingIndices<P> = List<ValidatorIndex, <P as Preset>::MaxValidatorsPerSlot>;

/// An aggregate of identical votes from one or more committees.
///
/// See EIP-7549 for aggregation across committees.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attestation<P: Preset> {
    /// Which committee members signed, across all aggregated committees.
    pub aggregation_bits: AggregationBits<P>,

    /// The vote.
    pub data: AttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,

    /// Which committees of the slot are aggregated.
    pub committee_bits: CommitteeBits<P>,
}

impl<P: Preset> Container for Attestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <AggregationBits<P>>::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
        <CommitteeBits<P>>::FIXED_SIZE,
    ];

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

    /// The vote reduced to the fields every fork shares.
    ///
    /// The committee bits name the committees, see EIP-7549.
    #[must_use]
    pub fn committee_vote(&self) -> CommitteeVote {
        CommitteeVote {
            data: self.data.clone(),
            signature: self.signature,
            committees: self.committee_indices().collect(),
            bits: self.aggregation_bits.iter().collect(),
            payload: PayloadClaim::Silent,
        }
    }
}

/// An attestation with its participants listed by validator index.
///
/// Slashing evidence uses this form, since it does not depend on committee shuffling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexedAttestation<P: Preset> {
    /// Participants, sorted and unique.
    pub attesting_indices: AttestingIndices<P>,

    /// The vote.
    pub data: AttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for IndexedAttestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <AttestingIndices<P>>::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

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

impl<P: Preset> IndexedAttestation<P> {
    /// The attestation a vote makes in this container.
    ///
    /// # Errors
    ///
    /// Fails when the vote has more signers than the committees of a slot hold.
    pub fn from_vote(vote: &IndexedVote) -> Result<Self, CapacityError> {
        Ok(Self {
            attesting_indices: List::try_from(vote.indices.clone())?,
            data: vote.data.clone(),
            signature: vote.signature,
        })
    }

    /// The vote reduced to the fields every fork shares.
    #[must_use]
    pub fn indexed_vote(&self) -> IndexedVote {
        IndexedVote {
            indices: self.attesting_indices.iter().copied().collect(),
            data: self.data.clone(),
            signature: self.signature,
        }
    }
}

/// One validator's attestation, as gossiped on a subnet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SingleAttestation {
    /// Committee of the attester.
    pub committee_index: CommitteeIndex,

    /// The attester.
    pub attester_index: ValidatorIndex,

    /// The vote.
    pub data: AttestationData,

    /// Attester's signature.
    pub signature: BlsSignature,
}

impl Container for SingleAttestation {
    const FIELDS: &'static [Option<usize>] = &[
        CommitteeIndex::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.committee_index);
        visitor.field(&self.attester_index);
        visitor.field(&self.data);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            committee_index: fields.field()?,
            attester_index: fields.field()?,
            data: fields.field()?,
            signature: fields.field()?,
        })
    }
}
