//! Blinded blocks of Electra, which add execution requests and committee-wide attestations.
//!
//! See the Electra builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    BlsSignature, Bytes32, Preset, Root, Slot, ValidatorIndex,
    electra::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, BeaconBlockHeader,
        BlobKzgCommitments, Deposit, Eth1Data, ExecutionPayload, ExecutionPayloadHeader,
        ExecutionRequests, ProposerSlashing, SignedBeaconBlock, SignedBlsToExecutionChange,
        SignedVoluntaryExit, SyncAggregate, UnblindError,
    },
};

/// The operations a block carries, with its payload reduced to a header.
///
/// See `BlindedBeaconBlockBody` in the Electra builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlindedBeaconBlockBody<P: Preset> {
    /// Proposer's signature over the epoch, mixed into the randomness.
    pub randao_reveal: BlsSignature,

    /// Proposer's eth1 data vote.
    pub eth1_data: Eth1Data,

    /// Free-form bytes chosen by the proposer.
    pub graffiti: Bytes32,

    /// Proposer slashings.
    pub proposer_slashings: List<ProposerSlashing, P::MaxProposerSlashings>,

    /// Attester slashings.
    pub attester_slashings: List<AttesterSlashing<P>, P::MaxAttesterSlashingsElectra>,

    /// Attestations.
    pub attestations: List<Attestation<P>, P::MaxAttestationsElectra>,

    /// Deposits from the deposit contract.
    pub deposits: List<Deposit, P::MaxDeposits>,

    /// Voluntary exits.
    pub voluntary_exits: List<SignedVoluntaryExit, P::MaxVoluntaryExits>,

    /// Sync committee signature over the parent.
    pub sync_aggregate: SyncAggregate<P>,

    /// Header of the execution payload.
    pub execution_payload_header: ExecutionPayloadHeader<P>,

    /// Withdrawal credential changes.
    pub bls_to_execution_changes: List<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges>,

    /// Commitments to the blobs, copied from the builder's bid.
    pub blob_kzg_commitments: BlobKzgCommitments<P>,

    /// Requests the payload produced, copied from the builder's bid.
    pub execution_requests: ExecutionRequests<P>,
}

impl<P: Preset> Container for BlindedBeaconBlockBody<P> {
    const FIELDS: &'static [Option<usize>] = &[
        BlsSignature::FIXED_SIZE,
        Eth1Data::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        <List<ProposerSlashing, P::MaxProposerSlashings>>::FIXED_SIZE,
        <List<AttesterSlashing<P>, P::MaxAttesterSlashingsElectra>>::FIXED_SIZE,
        <List<Attestation<P>, P::MaxAttestationsElectra>>::FIXED_SIZE,
        <List<Deposit, P::MaxDeposits>>::FIXED_SIZE,
        <List<SignedVoluntaryExit, P::MaxVoluntaryExits>>::FIXED_SIZE,
        <SyncAggregate<P>>::FIXED_SIZE,
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
        <List<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges>>::FIXED_SIZE,
        <BlobKzgCommitments<P>>::FIXED_SIZE,
        <ExecutionRequests<P>>::FIXED_SIZE,
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
        visitor.field(&self.execution_payload_header);
        visitor.field(&self.bls_to_execution_changes);
        visitor.field(&self.blob_kzg_commitments);
        visitor.field(&self.execution_requests);
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
            execution_payload_header: fields.field()?,
            bls_to_execution_changes: fields.field()?,
            blob_kzg_commitments: fields.field()?,
            execution_requests: fields.field()?,
        })
    }
}

impl<P: Preset> BlindedBeaconBlockBody<P> {
    /// The full body, with the payload the header commits to.
    ///
    /// # Errors
    ///
    /// Fails when the payload's root differs from the committed header's root.
    pub fn unblind(
        self,
        execution_payload: ExecutionPayload<P>,
    ) -> Result<BeaconBlockBody<P>, UnblindError> {
        UnblindError::check_payload(&self.execution_payload_header, &execution_payload)?;
        Ok(BeaconBlockBody {
            randao_reveal: self.randao_reveal,
            eth1_data: self.eth1_data,
            graffiti: self.graffiti,
            proposer_slashings: self.proposer_slashings,
            attester_slashings: self.attester_slashings,
            attestations: self.attestations,
            deposits: self.deposits,
            voluntary_exits: self.voluntary_exits,
            sync_aggregate: self.sync_aggregate,
            execution_payload,
            bls_to_execution_changes: self.bls_to_execution_changes,
            blob_kzg_commitments: self.blob_kzg_commitments,
            execution_requests: self.execution_requests,
        })
    }
}

impl<P: Preset> From<BeaconBlockBody<P>> for BlindedBeaconBlockBody<P> {
    /// The body with its payload reduced to a header, which keeps the body root.
    fn from(body: BeaconBlockBody<P>) -> Self {
        Self {
            execution_payload_header: (&body.execution_payload).into(),
            randao_reveal: body.randao_reveal,
            eth1_data: body.eth1_data,
            graffiti: body.graffiti,
            proposer_slashings: body.proposer_slashings,
            attester_slashings: body.attester_slashings,
            attestations: body.attestations,
            deposits: body.deposits,
            voluntary_exits: body.voluntary_exits,
            sync_aggregate: body.sync_aggregate,
            bls_to_execution_changes: body.bls_to_execution_changes,
            blob_kzg_commitments: body.blob_kzg_commitments,
            execution_requests: body.execution_requests,
        }
    }
}

/// A block whose body carries a payload header.
///
/// See `BlindedBeaconBlock` in the Electra builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlindedBeaconBlock<P: Preset> {
    /// Slot the block is proposed in.
    pub slot: Slot,

    /// The proposer.
    pub proposer_index: ValidatorIndex,

    /// Root of the parent block.
    pub parent_root: Root,

    /// Root of the post-state.
    pub state_root: Root,

    /// The blinded body.
    pub body: BlindedBeaconBlockBody<P>,
}

impl<P: Preset> Container for BlindedBeaconBlock<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        Root::FIXED_SIZE,
        Root::FIXED_SIZE,
        <BlindedBeaconBlockBody<P>>::FIXED_SIZE,
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

impl<P: Preset> BlindedBeaconBlock<P> {
    /// The header of this block, the same one the full block has.
    ///
    /// The blinded body hashes like the full body, so the body root is unchanged.
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

    /// The full block, with the payload the header commits to.
    ///
    /// # Errors
    ///
    /// Fails when the payload's root differs from the committed header's root.
    pub fn unblind(
        self,
        execution_payload: ExecutionPayload<P>,
    ) -> Result<BeaconBlock<P>, UnblindError> {
        Ok(BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body: self.body.unblind(execution_payload)?,
        })
    }
}

impl<P: Preset> From<BeaconBlock<P>> for BlindedBeaconBlock<P> {
    /// The block with its payload reduced to a header, which keeps the block root.
    fn from(block: BeaconBlock<P>) -> Self {
        Self {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body: block.body.into(),
        }
    }
}

/// A blinded block with its proposer's signature.
///
/// See `SignedBlindedBeaconBlock` in the Electra builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBlindedBeaconBlock<P: Preset> {
    /// The blinded block.
    pub message: BlindedBeaconBlock<P>,

    /// Proposer's signature, which also holds over the full block.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedBlindedBeaconBlock<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <BlindedBeaconBlock<P>>::FIXED_SIZE,
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

impl<P: Preset> SignedBlindedBeaconBlock<P> {
    /// The signed full block, with the payload the header commits to.
    ///
    /// Both blocks share one root, so the signature carries over unchanged.
    ///
    /// # Errors
    ///
    /// Fails when the payload's root differs from the committed header's root.
    pub fn unblind(
        self,
        execution_payload: ExecutionPayload<P>,
    ) -> Result<SignedBeaconBlock<P>, UnblindError> {
        Ok(SignedBeaconBlock {
            message: self.message.unblind(execution_payload)?,
            signature: self.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Minimal, electra::WithdrawalRequest};

    #[test]
    fn signed_blinded_block_round_trips_through_ssz() {
        // Fixture state: a blinded block at slot 13, one attestation, one withdrawal request.
        let mut signed = SignedBlindedBeaconBlock::<Minimal>::default();
        signed.message.slot = Slot(13);
        signed
            .message
            .body
            .attestations
            .push(Attestation::default())
            .unwrap();
        signed
            .message
            .body
            .execution_requests
            .withdrawals
            .push(WithdrawalRequest::default())
            .unwrap();
        signed.signature = BlsSignature([8; 96]);

        let decoded = SignedBlindedBeaconBlock::<Minimal>::decode(&signed.encode()).unwrap();

        assert_eq!(decoded, signed);
    }
}
