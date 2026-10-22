//! Sync committees, the rotating set that signs heads for light clients.

use axiom_ssz::{
    BitVector, Container, DecodeError, FieldDecoder, FieldVisitor, PersistentVector, Ssz, Vector,
};

use crate::{BlsPubkey, BlsSignature, Preset, Root, Slot, ValidatorIndex};

/// Which sync committee members signed.
pub type SyncCommitteeBits<P> = BitVector<<P as Preset>::SyncCommitteeSize>;

/// Which sync subcommittee members signed.
pub type SyncSubcommitteeBits<P> = BitVector<<P as Preset>::SyncSubcommitteeSize>;

/// The validators signing heads for one sync committee period.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncCommittee<P: Preset> {
    /// Member keys, possibly repeating a validator.
    pub pubkeys: PersistentVector<BlsPubkey, P::SyncCommitteeSize>,

    /// Sum of the member keys.
    pub aggregate_pubkey: BlsPubkey,
}

impl<P: Preset> Container for SyncCommittee<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <Vector<BlsPubkey, P::SyncCommitteeSize>>::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkeys);
        visitor.field(&self.aggregate_pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkeys: fields.field()?,
            aggregate_pubkey: fields.field()?,
        })
    }
}

/// The sync committee's aggregate signature over the parent block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncAggregate<P: Preset> {
    /// Which members signed.
    pub sync_committee_bits: SyncCommitteeBits<P>,

    /// Aggregate signature of the signers.
    pub sync_committee_signature: BlsSignature,
}

impl<P: Preset> Container for SyncAggregate<P> {
    const FIELDS: &'static [Option<usize>] =
        &[<SyncCommitteeBits<P>>::FIXED_SIZE, BlsSignature::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.sync_committee_bits);
        visitor.field(&self.sync_committee_signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            sync_committee_bits: fields.field()?,
            sync_committee_signature: fields.field()?,
        })
    }
}

/// One member's signature over a head block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncCommitteeMessage {
    /// Slot of the message.
    pub slot: Slot,

    /// Head block signed.
    pub beacon_block_root: Root,

    /// The signer.
    pub validator_index: ValidatorIndex,

    /// The signature.
    pub signature: BlsSignature,
}

impl Container for SyncCommitteeMessage {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        Root::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.beacon_block_root);
        visitor.field(&self.validator_index);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            beacon_block_root: fields.field()?,
            validator_index: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// A subcommittee's aggregate of sync messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncCommitteeContribution<P: Preset> {
    /// Slot of the messages.
    pub slot: Slot,

    /// Head block signed.
    pub beacon_block_root: Root,

    /// The subcommittee.
    pub subcommittee_index: u64,

    /// Which subcommittee members signed.
    pub aggregation_bits: SyncSubcommitteeBits<P>,

    /// Aggregate signature.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SyncCommitteeContribution<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        Root::FIXED_SIZE,
        u64::FIXED_SIZE,
        <SyncSubcommitteeBits<P>>::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.beacon_block_root);
        visitor.field(&self.subcommittee_index);
        visitor.field(&self.aggregation_bits);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            beacon_block_root: fields.field()?,
            subcommittee_index: fields.field()?,
            aggregation_bits: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// A contribution with proof its sender was selected to aggregate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContributionAndProof<P: Preset> {
    /// The aggregator.
    pub aggregator_index: ValidatorIndex,

    /// The contribution.
    pub contribution: SyncCommitteeContribution<P>,

    /// Proof of selection.
    pub selection_proof: BlsSignature,
}

impl<P: Preset> Container for ContributionAndProof<P> {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorIndex::FIXED_SIZE,
        <SyncCommitteeContribution<P>>::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.aggregator_index);
        visitor.field(&self.contribution);
        visitor.field(&self.selection_proof);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            aggregator_index: fields.field()?,
            contribution: fields.field()?,
            selection_proof: fields.field()?,
        })
    }
}

/// A contribution and proof, signed by the aggregator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedContributionAndProof<P: Preset> {
    /// The contribution and proof.
    pub message: ContributionAndProof<P>,

    /// Aggregator's signature.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedContributionAndProof<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ContributionAndProof<P>>::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.message);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            message: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// What a sync aggregator signs to prove selection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncAggregatorSelectionData {
    /// Slot of the selection.
    pub slot: Slot,

    /// Subcommittee of the selection.
    pub subcommittee_index: u64,
}

impl Container for SyncAggregatorSelectionData {
    const FIELDS: &'static [Option<usize>] = &[Slot::FIXED_SIZE, u64::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.subcommittee_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            subcommittee_index: fields.field()?,
        })
    }
}
