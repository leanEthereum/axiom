//! Blinded blocks of Bellatrix, which carry a payload header in place of the payload.
//!
//! A proposer signs a blinded block before it sees the payload a builder sold it.
//! The signature still holds over the full block.
//! A payload header hashes like its payload, so both bodies share one root.
//! See the Bellatrix builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};
use thiserror::Error;

use crate::{
    BlsSignature, Bytes32, Preset, Root, Slot, ValidatorIndex,
    bellatrix::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Deposit,
        Eth1Data, ExecutionPayload, ExecutionPayloadHeader, ProposerSlashing, SignedBeaconBlock,
        SignedVoluntaryExit, SyncAggregate,
    },
};

/// A payload that does not match the header a blinded block committed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum UnblindError {
    /// The payload's root differs from the committed header's root.
    #[error("payload root {actual} differs from the committed header root {committed}")]
    PayloadMismatch {
        /// Root of the header the block committed to.
        committed: Root,
        /// Root of the payload offered in its place.
        actual: Root,
    },
}

impl UnblindError {
    /// Accepts a payload only when it hashes like the committed header.
    ///
    /// A header and its payload share one root.
    /// So equal roots mean the payload is the committed one.
    pub(crate) fn check_payload(header: &impl Ssz, payload: &impl Ssz) -> Result<(), Self> {
        let committed = header.hash_tree_root();
        let actual = payload.hash_tree_root();
        if committed == actual {
            Ok(())
        } else {
            Err(Self::PayloadMismatch { committed, actual })
        }
    }
}

/// The operations a block carries, with its payload reduced to a header.
///
/// See `BlindedBeaconBlockBody` in the Bellatrix builder spec.
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
    pub attester_slashings: List<AttesterSlashing<P>, P::MaxAttesterSlashings>,

    /// Attestations.
    pub attestations: List<Attestation<P>, P::MaxAttestations>,

    /// Deposits from the deposit contract.
    pub deposits: List<Deposit, P::MaxDeposits>,

    /// Voluntary exits.
    pub voluntary_exits: List<SignedVoluntaryExit, P::MaxVoluntaryExits>,

    /// Sync committee signature over the parent.
    pub sync_aggregate: SyncAggregate<P>,

    /// Header of the execution payload.
    pub execution_payload_header: ExecutionPayloadHeader<P>,
}

impl<P: Preset> Container for BlindedBeaconBlockBody<P> {
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
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
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
        }
    }
}

/// A block whose body carries a payload header.
///
/// See `BlindedBeaconBlock` in the Bellatrix builder spec.
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
/// See `SignedBlindedBeaconBlock` in the Bellatrix builder spec.
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
    use crate::{Hash32, Minimal};

    #[test]
    fn signed_blinded_block_round_trips_through_ssz() {
        // Fixture state: a blinded block at slot 5 committing to payload block hash 0x0606...06.
        let mut signed = SignedBlindedBeaconBlock::<Minimal>::default();
        signed.message.slot = Slot(5);
        signed.message.body.execution_payload_header.block_hash = Hash32([6; 32]);
        signed.signature = BlsSignature([8; 96]);

        let decoded = SignedBlindedBeaconBlock::<Minimal>::decode(&signed.encode()).unwrap();

        assert_eq!(decoded, signed);
    }
}
