//! Builder API messages of Fulu, whose revealed blobs carry cell proofs.
//!
//! The bid is Electra's.
//! See the Fulu builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    KzgCommitment, KzgProof, Preset,
    fulu::{Blob, ExecutionPayload},
};

/// The blobs of a payload, with their commitments and the cell proofs of each extended blob.
///
/// See `BlobsBundle` in the Fulu builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobsBundle<P: Preset> {
    /// Commitments to the blobs, in blob order.
    pub commitments: List<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,

    /// Cell proofs of every extended blob, blob after blob, see EIP-7594.
    pub proofs: List<KzgProof, P::MaxCellProofsPerBlock>,

    /// The blobs.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for BlobsBundle<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <List<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
        <List<KzgProof, P::MaxCellProofsPerBlock>>::FIXED_SIZE,
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
/// See `ExecutionPayloadAndBlobsBundle` in the Fulu builder spec.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash32, Minimal};

    #[test]
    fn payload_and_blobs_round_trip_through_ssz() {
        // Fixture state: payload block hash 0x0303...03 with one blob and its 128 cell proofs.
        let mut revealed = ExecutionPayloadAndBlobsBundle::<Minimal>::default();
        revealed.execution_payload.block_hash = Hash32([3; 32]);
        revealed
            .blobs_bundle
            .commitments
            .push(KzgCommitment([4; 48]))
            .unwrap();
        revealed
            .blobs_bundle
            .blobs
            .push(Blob::<Minimal>::default())
            .unwrap();
        for byte in 0..128 {
            revealed
                .blobs_bundle
                .proofs
                .push(KzgProof([byte; 48]))
                .unwrap();
        }

        let decoded =
            ExecutionPayloadAndBlobsBundle::<Minimal>::decode(&revealed.encode()).unwrap();

        assert_eq!(decoded, revealed);
    }
}
