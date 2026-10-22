//! Light client data of Capella, whose headers carry the execution payload header.
//!
//! See the Capella light client sync protocol.

use axiom_ssz::{Const, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, Vector};

use crate::{
    Bytes32, Preset, Slot,
    capella::{
        BeaconBlockHeader, CurrentSyncCommitteeBranch, ExecutionPayloadHeader, FinalityBranch,
        NextSyncCommitteeBranch, SyncAggregate, SyncCommittee,
    },
};

/// Branch from the execution payload to the body root, depth floorlog2(25).
pub type ExecutionBranch = Vector<Bytes32, Const<4>>;

/// A beacon header with its execution payload header and proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LightClientHeader<P: Preset> {
    /// The beacon header.
    pub beacon: BeaconBlockHeader,

    /// Header of the block's execution payload.
    pub execution: ExecutionPayloadHeader<P>,

    /// Branch from the payload header to the body root.
    pub execution_branch: ExecutionBranch,
}

impl<P: Preset> Container for LightClientHeader<P> {
    const FIELDS: &'static [Option<usize>] = &[
        BeaconBlockHeader::FIXED_SIZE,
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
        ExecutionBranch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.beacon);
        visitor.field(&self.execution);
        visitor.field(&self.execution_branch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            beacon: fields.field()?,
            execution: fields.field()?,
            execution_branch: fields.field()?,
        })
    }
}

/// What a light client needs to start following from a trusted block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LightClientBootstrap<P: Preset> {
    /// The trusted block.
    pub header: LightClientHeader<P>,

    /// Sync committee of the block's period.
    pub current_sync_committee: SyncCommittee<P>,

    /// Proof of that committee against the state root.
    pub current_sync_committee_branch: CurrentSyncCommitteeBranch,
}

impl<P: Preset> Container for LightClientBootstrap<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <LightClientHeader<P>>::FIXED_SIZE,
        <SyncCommittee<P>>::FIXED_SIZE,
        CurrentSyncCommitteeBranch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.header);
        visitor.field(&self.current_sync_committee);
        visitor.field(&self.current_sync_committee_branch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: fields.field()?,
            current_sync_committee: fields.field()?,
            current_sync_committee_branch: fields.field()?,
        })
    }
}

/// A signed head, with the next sync committee and finality proofs.
///
/// An all-zero branch marks a proof the update does not carry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LightClientUpdate<P: Preset> {
    /// Header the sync committee signed.
    pub attested_header: LightClientHeader<P>,

    /// Sync committee of the next period.
    pub next_sync_committee: SyncCommittee<P>,

    /// Proof of the next committee against the attested state.
    pub next_sync_committee_branch: NextSyncCommitteeBranch,

    /// Header finalized by the attested state.
    pub finalized_header: LightClientHeader<P>,

    /// Proof of the finalized root against the attested state.
    pub finality_branch: FinalityBranch,

    /// Sync committee signature over the attested header.
    pub sync_aggregate: SyncAggregate<P>,

    /// Slot of the block carrying the signature.
    pub signature_slot: Slot,
}

impl<P: Preset> Container for LightClientUpdate<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <LightClientHeader<P>>::FIXED_SIZE,
        <SyncCommittee<P>>::FIXED_SIZE,
        NextSyncCommitteeBranch::FIXED_SIZE,
        <LightClientHeader<P>>::FIXED_SIZE,
        FinalityBranch::FIXED_SIZE,
        <SyncAggregate<P>>::FIXED_SIZE,
        Slot::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.attested_header);
        visitor.field(&self.next_sync_committee);
        visitor.field(&self.next_sync_committee_branch);
        visitor.field(&self.finalized_header);
        visitor.field(&self.finality_branch);
        visitor.field(&self.sync_aggregate);
        visitor.field(&self.signature_slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attested_header: fields.field()?,
            next_sync_committee: fields.field()?,
            next_sync_committee_branch: fields.field()?,
            finalized_header: fields.field()?,
            finality_branch: fields.field()?,
            sync_aggregate: fields.field()?,
            signature_slot: fields.field()?,
        })
    }
}

impl<P: Preset> LightClientUpdate<P> {
    /// Whether the update carries a next sync committee.
    #[must_use]
    pub fn is_sync_committee_update(&self) -> bool {
        self.next_sync_committee_branch
            .iter()
            .any(|node| node.0 != [0; 32])
    }

    /// Whether the update proves a finalized header.
    #[must_use]
    pub fn is_finality_update(&self) -> bool {
        self.finality_branch.iter().any(|node| node.0 != [0; 32])
    }
}

/// A signed head with a finality proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LightClientFinalityUpdate<P: Preset> {
    /// Header the sync committee signed.
    pub attested_header: LightClientHeader<P>,

    /// Header finalized by the attested state.
    pub finalized_header: LightClientHeader<P>,

    /// Proof of the finalized root against the attested state.
    pub finality_branch: FinalityBranch,

    /// Sync committee signature over the attested header.
    pub sync_aggregate: SyncAggregate<P>,

    /// Slot of the block carrying the signature.
    pub signature_slot: Slot,
}

impl<P: Preset> Container for LightClientFinalityUpdate<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <LightClientHeader<P>>::FIXED_SIZE,
        <LightClientHeader<P>>::FIXED_SIZE,
        FinalityBranch::FIXED_SIZE,
        <SyncAggregate<P>>::FIXED_SIZE,
        Slot::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.attested_header);
        visitor.field(&self.finalized_header);
        visitor.field(&self.finality_branch);
        visitor.field(&self.sync_aggregate);
        visitor.field(&self.signature_slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attested_header: fields.field()?,
            finalized_header: fields.field()?,
            finality_branch: fields.field()?,
            sync_aggregate: fields.field()?,
            signature_slot: fields.field()?,
        })
    }
}

/// A signed head, without finality.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LightClientOptimisticUpdate<P: Preset> {
    /// Header the sync committee signed.
    pub attested_header: LightClientHeader<P>,

    /// Sync committee signature over the attested header.
    pub sync_aggregate: SyncAggregate<P>,

    /// Slot of the block carrying the signature.
    pub signature_slot: Slot,
}

impl<P: Preset> Container for LightClientOptimisticUpdate<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <LightClientHeader<P>>::FIXED_SIZE,
        <SyncAggregate<P>>::FIXED_SIZE,
        Slot::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.attested_header);
        visitor.field(&self.sync_aggregate);
        visitor.field(&self.signature_slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attested_header: fields.field()?,
            sync_aggregate: fields.field()?,
            signature_slot: fields.field()?,
        })
    }
}
