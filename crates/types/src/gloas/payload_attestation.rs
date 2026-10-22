//! Payload attestations, the payload timeliness committee's votes on whether a payload arrived.
//!
//! See EIP-7732 and the Gloas beacon chain spec.

use axiom_ssz::{
    BitVector, Container, DecodeError, FieldDecoder, FieldVisitor, List, Merkleization,
    ProgressiveList, Ssz, Vector,
};

use crate::{BlsSignature, Preset, Root, Slot, ValidatorIndex};

/// Members of one slot's payload timeliness committee.
pub type PayloadTimelinessCommittee<P> = Vector<ValidatorIndex, <P as Preset>::PtcSize>;

/// Indices of the committee members behind a payload attestation.
pub type PayloadTimelinessCommitteeIndices<P> = List<ValidatorIndex, <P as Preset>::PtcSize>;

/// Which committee members signed, one bit per member in committee order.
pub type PayloadTimelinessCommitteeBits<P> = BitVector<<P as Preset>::PtcSize>;

/// Committees of the previous, current, and next epochs, one per slot.
pub type PayloadTimelinessCommitteeWindow<P> =
    Vector<PayloadTimelinessCommittee<P>, <P as Preset>::PtcWindowSlots>;

/// Payload attestations a block carries.
pub type PayloadAttestations<P> = ProgressiveList<PayloadAttestation<P>>;

/// What a payload timeliness committee member votes on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttestationData {
    /// Block whose payload is judged.
    pub beacon_block_root: Root,

    /// Slot of that block.
    pub slot: Slot,

    /// Whether the payload arrived in time.
    pub payload_present: bool,

    /// Whether the payload's blob data was available.
    pub blob_data_available: bool,
}

impl Container for PayloadAttestationData {
    const FIELDS: &'static [Option<usize>] = &[
        Root::FIXED_SIZE,
        Slot::FIXED_SIZE,
        bool::FIXED_SIZE,
        bool::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.beacon_block_root);
        visitor.field(&self.slot);
        visitor.field(&self.payload_present);
        visitor.field(&self.blob_data_available);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            beacon_block_root: fields.field()?,
            slot: fields.field()?,
            payload_present: fields.field()?,
            blob_data_available: fields.field()?,
        })
    }
}

/// An aggregate of identical payload votes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttestation<P: Preset> {
    /// Which committee members signed.
    pub aggregation_bits: PayloadTimelinessCommitteeBits<P>,

    /// The vote.
    pub data: PayloadAttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for PayloadAttestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <PayloadTimelinessCommitteeBits<P>>::FIXED_SIZE,
        PayloadAttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 3]);

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

/// One committee member's payload vote, as gossiped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttestationMessage {
    /// The voter.
    pub validator_index: ValidatorIndex,

    /// The vote.
    pub data: PayloadAttestationData,

    /// Voter's signature.
    pub signature: BlsSignature,
}

impl Container for PayloadAttestationMessage {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorIndex::FIXED_SIZE,
        PayloadAttestationData::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.validator_index);
        visitor.field(&self.data);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            validator_index: fields.field()?,
            data: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// A payload attestation with its participants listed by validator index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexedPayloadAttestation<P: Preset> {
    /// Participants, sorted.
    pub attesting_indices: PayloadTimelinessCommitteeIndices<P>,

    /// The vote.
    pub data: PayloadAttestationData,

    /// Aggregate signature of every participant.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for IndexedPayloadAttestation<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <PayloadTimelinessCommitteeIndices<P>>::FIXED_SIZE,
        PayloadAttestationData::FIXED_SIZE,
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
