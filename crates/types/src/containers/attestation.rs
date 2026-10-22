//! Attestations, the votes that drive fork choice and finality.

use axiom_ssz::{
    BitList, BitVector, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz,
};

use crate::{BlsSignature, Checkpoint, CommitteeIndex, Preset, Root, Slot, ValidatorIndex};

/// Participation bits of every committee in an attestation, concatenated in committee order.
pub type AggregationBits<P> = BitList<<P as Preset>::MaxValidatorsPerSlot>;

/// The committees an attestation aggregates.
pub type CommitteeBits<P> = BitVector<<P as Preset>::MaxCommitteesPerSlot>;

/// Indices of the validators behind an attestation, sorted and unique.
pub type AttestingIndices<P> = List<ValidatorIndex, <P as Preset>::MaxValidatorsPerSlot>;

/// What an attester votes for: a head block and a source-target link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationData {
    /// Slot the vote is cast in.
    pub slot: Slot,

    /// Committee index, zero since Electra moved it to the committee bits.
    pub index: CommitteeIndex,

    /// Head block, the LMD-GHOST vote.
    pub beacon_block_root: Root,

    /// Latest justified checkpoint, the source of the FFG vote.
    pub source: Checkpoint,

    /// Checkpoint of the current epoch, the target of the FFG vote.
    pub target: Checkpoint,
}

impl Container for AttestationData {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        CommitteeIndex::FIXED_SIZE,
        Root::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.index);
        visitor.field(&self.beacon_block_root);
        visitor.field(&self.source);
        visitor.field(&self.target);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            index: fields.field()?,
            beacon_block_root: fields.field()?,
            source: fields.field()?,
            target: fields.field()?,
        })
    }
}

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

impl AttestationData {
    /// Whether two votes violate a Casper FFG commandment together.
    ///
    /// A double vote names two targets for one epoch.
    /// A surround vote spans a link strictly inside the other.
    /// See `is_slashable_attestation_data` in the phase0 beacon chain spec.
    #[must_use]
    pub fn is_slashable_with(&self, other: &Self) -> bool {
        let double_vote = self != other && self.target.epoch == other.target.epoch;
        let surround_vote =
            self.source.epoch < other.source.epoch && other.target.epoch < self.target.epoch;
        double_vote || surround_vote
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
