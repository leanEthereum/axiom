//! Beacon block bodies of Bellatrix, which carry an execution payload.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    BlsSignature, Bytes32, Preset, Root, Slot, ValidatorIndex,
    bellatrix::{
        Attestation, AttesterSlashing, BeaconBlockHeader, Deposit, Eth1Data, ExecutionPayload,
        NewPayloadRequest, ProposerSlashing, SignedVoluntaryExit, SyncAggregate,
    },
};

/// The operations and payload a block carries.
///
/// See the Bellatrix beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeaconBlockBody<P: Preset> {
    /// Proposer's signature over the epoch, mixed into the randomness.
    pub randao_reveal: BlsSignature,

    /// Proposer's eth1 data vote.
    pub eth1_data: Eth1Data,

    /// Free-form bytes chosen by the proposer.
    pub graffiti: Bytes32,

    /// Proposer slashings.
    pub proposer_slashings: List<ProposerSlashing, P::MaxProposerSlashings>,

    /// Attester slashings.
    pub attester_slashings: List<AttesterSlashing<P>, P::MaxAttesterSlashings>,

    /// Attestations.
    pub attestations: List<Attestation<P>, P::MaxAttestations>,

    /// Deposits from the deposit contract.
    pub deposits: List<Deposit, P::MaxDeposits>,

    /// Voluntary exits.
    pub voluntary_exits: List<SignedVoluntaryExit, P::MaxVoluntaryExits>,

    /// Sync committee signature over the parent.
    pub sync_aggregate: SyncAggregate<P>,

    /// The execution payload.
    pub execution_payload: ExecutionPayload<P>,
}

impl<P: Preset> Container for BeaconBlockBody<P> {
    const FIELDS: &'static [Option<usize>] = &[
        BlsSignature::FIXED_SIZE,
        Eth1Data::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        <List<ProposerSlashing, P::MaxProposerSlashings>>::FIXED_SIZE,
        <List<AttesterSlashing<P>, P::MaxAttesterSlashings>>::FIXED_SIZE,
        <List<Attestation<P>, P::MaxAttestations>>::FIXED_SIZE,
        <List<Deposit, P::MaxDeposits>>::FIXED_SIZE,
        <List<SignedVoluntaryExit, P::MaxVoluntaryExits>>::FIXED_SIZE,
        <SyncAggregate<P>>::FIXED_SIZE,
        <ExecutionPayload<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.randao_reveal);
        visitor.field(&self.eth1_data);
        visitor.field(&self.graffiti);
        visitor.field(&self.proposer_slashings);
        visitor.field(&self.attester_slashings);
        visitor.field(&self.attestations);
        visitor.field(&self.deposits);
        visitor.field(&self.voluntary_exits);
        visitor.field(&self.sync_aggregate);
        visitor.field(&self.execution_payload);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            randao_reveal: fields.field()?,
            eth1_data: fields.field()?,
            graffiti: fields.field()?,
            proposer_slashings: fields.field()?,
            attester_slashings: fields.field()?,
            attestations: fields.field()?,
            deposits: fields.field()?,
            voluntary_exits: fields.field()?,
            sync_aggregate: fields.field()?,
            execution_payload: fields.field()?,
        })
    }
}

/// A block: its place in the chain and its body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeaconBlock<P: Preset> {
    /// Slot the block is proposed in.
    pub slot: Slot,

    /// The proposer.
    pub proposer_index: ValidatorIndex,

    /// Root of the parent block.
    pub parent_root: Root,

    /// Root of the post-state.
    pub state_root: Root,

    /// The body.
    pub body: BeaconBlockBody<P>,
}

impl<P: Preset> Container for BeaconBlock<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        Root::FIXED_SIZE,
        Root::FIXED_SIZE,
        <BeaconBlockBody<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.proposer_index);
        visitor.field(&self.parent_root);
        visitor.field(&self.state_root);
        visitor.field(&self.body);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            proposer_index: fields.field()?,
            parent_root: fields.field()?,
            state_root: fields.field()?,
            body: fields.field()?,
        })
    }
}

impl<P: Preset> BeaconBlock<P> {
    /// The header of this block, which hashes to the same root.
    ///
    /// The body is replaced by its root, so the header proves the block without carrying it.
    #[must_use]
    pub fn header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body.hash_tree_root(),
        }
    }

    /// The request the execution engine judges for this block's payload.
    ///
    /// See `process_execution_payload` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn new_payload_request(&self) -> NewPayloadRequest<P> {
        NewPayloadRequest {
            execution_payload: self.body.execution_payload.clone(),
        }
    }
}

/// A block with its proposer's signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBeaconBlock<P: Preset> {
    /// The block.
    pub message: BeaconBlock<P>,

    /// Proposer's signature.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedBeaconBlock<P> {
    const FIELDS: &'static [Option<usize>] =
        &[<BeaconBlock<P>>::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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
