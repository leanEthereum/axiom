//! Attestations, the votes that drive fork choice and finality.

use axiom_ssz::{BitList, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{BlsSignature, CommitteeIndex, Preset, Root, Slot, ValidatorIndex, phase0::Checkpoint};

/// Participation bits of the one committee an attestation covers.
pub type AggregationBits<P> = BitList<<P as Preset>::MaxValidatorsPerCommittee>;

/// Indices of the validators behind an attestation, sorted and unique.
pub type AttestingIndices<P> = List<ValidatorIndex, <P as Preset>::MaxValidatorsPerCommittee>;

/// What an attester votes for: a head block and a source-target link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationData {
    /// Slot the vote is cast in.
    pub slot: Slot,

    /// Committee of the attesters, always zero from Electra on, where the committee bits name it.
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

/// An aggregate of identical votes from one committee.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attestation<P: Preset> {
    /// Which committee members signed.
    pub aggregation_bits: AggregationBits<P>,

    /// The vote.
    pub data: AttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for Attestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <AggregationBits<P>>::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.aggregation_bits);
        visitor.field(&self.data);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            aggregation_bits: fields.field()?,
            data: fields.field()?,
            signature: fields.field()?,
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

/// An attestation kept in the state until its epoch is scored.
///
/// Altair replaced these lists with per-validator participation flags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingAttestation<P: Preset> {
    /// Which committee members signed.
    pub aggregation_bits: AggregationBits<P>,

    /// The vote.
    pub data: AttestationData,

    /// Slots between the vote and the block that included it.
    pub inclusion_delay: Slot,

    /// Proposer of the including block, who earns a share of the reward.
    pub proposer_index: ValidatorIndex,
}

impl<P: Preset> Container for PendingAttestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <AggregationBits<P>>::FIXED_SIZE,
        AttestationData::FIXED_SIZE,
        Slot::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.aggregation_bits);
        visitor.field(&self.data);
        visitor.field(&self.inclusion_delay);
        visitor.field(&self.proposer_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            aggregation_bits: fields.field()?,
            data: fields.field()?,
            inclusion_delay: fields.field()?,
            proposer_index: fields.field()?,
        })
    }
}
