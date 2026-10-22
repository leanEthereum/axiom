//! Builder API messages of Deneb, which carry blobs beside the payload.
//!
//! A bid commits to the blobs, and the revealed payload brings them with their proofs.
//! See the Deneb builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, U256};

use crate::{
    BlsPubkey, BlsSignature, KzgCommitment, KzgProof, Preset,
    deneb::{Blob, BlobKzgCommitments, ExecutionPayload, ExecutionPayloadHeader},
};

/// The blobs of a payload, with their commitments and one proof per blob.
///
/// See `BlobsBundle` in the Deneb builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobsBundle<P: Preset> {
    /// Commitments to the blobs, in blob order.
    pub commitments: List<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,

    /// Proofs that open each commitment to its blob, in blob order.
    pub proofs: List<KzgProof, P::MaxBlobCommitmentsPerBlock>,

    /// The blobs.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for BlobsBundle<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <List<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
        <List<KzgProof, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
        <List<Blob<P>, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.commitments);
        visitor.field(&self.proofs);
        visitor.field(&self.blobs);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            commitments: fields.field()?,
            proofs: fields.field()?,
            blobs: fields.field()?,
        })
    }
}

/// A revealed payload with the blobs its transactions carry.
///
/// See `ExecutionPayloadAndBlobsBundle` in the Deneb builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPayloadAndBlobsBundle<P: Preset> {
    /// The payload.
    pub execution_payload: ExecutionPayload<P>,

    /// The payload's blobs.
    pub blobs_bundle: BlobsBundle<P>,
}

impl<P: Preset> Container for ExecutionPayloadAndBlobsBundle<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayload<P>>::FIXED_SIZE,
        <BlobsBundle<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.execution_payload);
        visitor.field(&self.blobs_bundle);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            execution_payload: fields.field()?,
            blobs_bundle: fields.field()?,
        })
    }
}

/// A builder's offer of a payload, committed to by its header and its blobs.
///
/// See `BuilderBid` in the Deneb builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderBid<P: Preset> {
    /// Header of the offered payload.
    pub header: ExecutionPayloadHeader<P>,

    /// Commitments to the payload's blobs, which the blinded block must carry.
    pub blob_kzg_commitments: BlobKzgCommitments<P>,

    /// Wei the proposer's fee recipient receives.
    pub value: U256,

    /// The bidding builder.
    pub pubkey: BlsPubkey,
}

impl<P: Preset> Container for BuilderBid<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
        <BlobKzgCommitments<P>>::FIXED_SIZE,
        U256::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.header);
        visitor.field(&self.blob_kzg_commitments);
        visitor.field(&self.value);
        visitor.field(&self.pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: fields.field()?,
            blob_kzg_commitments: fields.field()?,
            value: fields.field()?,
            pubkey: fields.field()?,
        })
    }
}

/// A bid with its builder's signature.
///
/// See `SignedBuilderBid` in the Deneb builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBuilderBid<P: Preset> {
    /// The bid.
    pub message: BuilderBid<P>,

    /// Builder's signature in the application builder domain.
    pub signature: BlsSignature,
}

impl<P: Preset> Container for SignedBuilderBid<P> {
    const FIELDS: &'static [Option<usize>] =
        &[<BuilderBid<P>>::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash32, Minimal};

    #[test]
    fn bid_round_trips_through_ssz() {
        // Fixture state: a bid of 9 wei committing to two blobs.
        let mut bid = SignedBuilderBid::<Minimal>::default();
        bid.message.header.blob_gas_used = 262_144;
        for byte in [1, 2] {
            bid.message
                .blob_kzg_commitments
                .push(KzgCommitment([byte; 48]))
                .unwrap();
        }
        bid.message.value = U256::from(9);
        bid.signature = BlsSignature([1; 96]);

        let decoded = SignedBuilderBid::<Minimal>::decode(&bid.encode()).unwrap();

        assert_eq!(decoded, bid);
    }

    #[test]
    fn payload_and_blobs_round_trip_through_ssz() {
        // Fixture state: payload block hash 0x0303...03 with one blob, its commitment and proof.
        let mut revealed = ExecutionPayloadAndBlobsBundle::<Minimal>::default();
        revealed.execution_payload.block_hash = Hash32([3; 32]);
        revealed
            .blobs_bundle
            .commitments
            .push(KzgCommitment([4; 48]))
            .unwrap();
        revealed
            .blobs_bundle
            .proofs
            .push(KzgProof([5; 48]))
            .unwrap();
        revealed
            .blobs_bundle
            .blobs
            .push(Blob::<Minimal>::default())
            .unwrap();

        let decoded =
            ExecutionPayloadAndBlobsBundle::<Minimal>::decode(&revealed.encode()).unwrap();

        assert_eq!(decoded, revealed);
    }
}
