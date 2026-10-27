//! A block bundled with its payload envelope and blobs, for a proposer that builds its own payload.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    KzgProof, Preset,
    hstar::{BeaconBlock, Blob, ExecutionPayloadEnvelope},
};

/// A block to sign, with the payload envelope it bids for and that payload's blobs.
///
/// One response holds everything to publish, so another node can publish it after a failover.
/// It is the Hstar response of the produce-block route, not a consensus container.
/// See `BlockContents` in the beacon-APIs repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockContents<P: Preset> {
    /// The unsigned block.
    pub block: BeaconBlock<P>,

    /// The unsigned envelope that reveals the block's payload.
    pub execution_payload_envelope: ExecutionPayloadEnvelope<P>,

    /// Cell proofs of every extended blob, blob after blob.
    pub kzg_proofs: List<KzgProof, P::MaxCellProofsPerBlock>,

    /// The blobs, in commitment order.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for BlockContents<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <BeaconBlock<P>>::FIXED_SIZE,
        <ExecutionPayloadEnvelope<P>>::FIXED_SIZE,
        <List<KzgProof, P::MaxCellProofsPerBlock>>::FIXED_SIZE,
        <List<Blob<P>, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block);
        visitor.field(&self.execution_payload_envelope);
        visitor.field(&self.kzg_proofs);
        visitor.field(&self.blobs);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block: fields.field()?,
            execution_payload_envelope: fields.field()?,
            kzg_proofs: fields.field()?,
            blobs: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Minimal, Root, Slot};

    #[test]
    fn contents_round_trip_through_ssz() {
        // Fixture state: a block at slot 3, its envelope naming block root 0x0909...09.
        // The payload carries one blob, so the bundle holds that blob and its 128 cell proofs.
        let mut contents = BlockContents::<Minimal>::default();
        contents.block.slot = Slot(3);
        contents.execution_payload_envelope.beacon_block_root = Root([9; 32]);
        contents.blobs.push(Blob::<Minimal>::default()).unwrap();
        for byte in 0..128 {
            contents.kzg_proofs.push(KzgProof([byte; 48])).unwrap();
        }

        let decoded = BlockContents::<Minimal>::decode(&contents.encode()).unwrap();

        assert_eq!(decoded, contents);
    }
}
