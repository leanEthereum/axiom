//! Beacon block bodies of Hstar, which carry post-quantum key registrations.
//!
//! The body is Gloas's, with one field appended, see EIP-8450.

use axiom_ssz::{
    Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, ProgressiveList, Ssz,
};

use crate::{
    BlsSignature, Bytes32, Preset, Root, Slot, ValidatorIndex,
    hstar::{
        Attestation, AttesterSlashing, BeaconBlockHeader, Deposit, Eth1Data, ExecutionRequests,
        PayloadAttestations, PqKeyRegistrations, ProposerSlashing, SignedBlsToExecutionChange,
        SignedExecutionPayloadBid, SignedVoluntaryExit, SyncAggregate,
    },
};

/// The operations and bid a block carries.
///
/// See the Gloas beacon chain spec and EIP-8450.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeaconBlockBody<P: Preset> {
    /// Proposer's signature over the epoch, mixed into the randomness.
    pub randao_reveal: BlsSignature,

    /// Proposer's eth1 data vote.
    pub eth1_data: Eth1Data,

    /// Free-form bytes chosen by the proposer.
    pub graffiti: Bytes32,

    /// Proposer slashings.
    pub proposer_slashings: ProgressiveList<ProposerSlashing>,

    /// Attester slashings.
    pub attester_slashings: ProgressiveList<AttesterSlashing>,

    /// Attestations.
    pub attestations: ProgressiveList<Attestation<P>>,

    /// Deposits from the deposit contract.
    pub deposits: ProgressiveList<Deposit>,

    /// Voluntary exits.
    pub voluntary_exits: ProgressiveList<SignedVoluntaryExit>,

    /// Sync committee signature over the parent.
    pub sync_aggregate: SyncAggregate<P>,

    /// Withdrawal credential changes.
    pub bls_to_execution_changes: ProgressiveList<SignedBlsToExecutionChange>,

    /// The builder's signed bid for this slot's payload.
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,

    /// Votes of the payload timeliness committee on the parent's payload.
    pub payload_attestations: PayloadAttestations<P>,

    /// Requests from the execution layer of the parent's payload.
    pub parent_execution_requests: ExecutionRequests,

    /// Post-quantum key registrations, see EIP-8450.
    pub pq_key_registrations: PqKeyRegistrations,
}

impl<P: Preset> Container for BeaconBlockBody<P> {
    const FIELDS: &'static [Option<usize>] = &[
        BlsSignature::FIXED_SIZE,
        Eth1Data::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        <ProgressiveList<ProposerSlashing>>::FIXED_SIZE,
        <ProgressiveList<AttesterSlashing>>::FIXED_SIZE,
        <ProgressiveList<Attestation<P>>>::FIXED_SIZE,
        <ProgressiveList<Deposit>>::FIXED_SIZE,
        <ProgressiveList<SignedVoluntaryExit>>::FIXED_SIZE,
        <SyncAggregate<P>>::FIXED_SIZE,
        <ProgressiveList<SignedBlsToExecutionChange>>::FIXED_SIZE,
        SignedExecutionPayloadBid::FIXED_SIZE,
        <PayloadAttestations<P>>::FIXED_SIZE,
        ExecutionRequests::FIXED_SIZE,
        PqKeyRegistrations::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 14]);

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
        visitor.field(&self.bls_to_execution_changes);
        visitor.field(&self.signed_execution_payload_bid);
        visitor.field(&self.payload_attestations);
        visitor.field(&self.parent_execution_requests);
        visitor.field(&self.pq_key_registrations);
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
            bls_to_execution_changes: fields.field()?,
            signed_execution_payload_bid: fields.field()?,
            payload_attestations: fields.field()?,
            parent_execution_requests: fields.field()?,
            pq_key_registrations: fields.field()?,
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
