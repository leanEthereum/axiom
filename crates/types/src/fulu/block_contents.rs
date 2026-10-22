//! A block bundled with its blobs, the unit a proposer publishes.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    BlsSignature, KzgProof, Preset,
    fulu::{BeaconBlock, Blob, SignedBeaconBlock},
};

/// A signed block with every blob it commits to and their cell proofs.
///
/// A proposer holds all of its blobs, so the node can build every column from this.
/// This is the Fulu body of the publish-block route in the beacon API, not a consensus container.
/// See `SignedBlockContents` in the beacon-APIs repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBlockContents<P: Preset> {
    /// The block.
    pub signed_block: SignedBeaconBlock<P>,

    /// Cell proofs of every extended blob, blob after blob.
    pub kzg_proofs: List<KzgProof, P::MaxCellProofsPerBlock>,

    /// The blobs, in commitment order.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for SignedBlockContents<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <SignedBeaconBlock<P>>::FIXED_SIZE,
        <List<KzgProof, P::MaxCellProofsPerBlock>>::FIXED_SIZE,
        <List<Blob<P>, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.signed_block);
        visitor.field(&self.kzg_proofs);
        visitor.field(&self.blobs);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            signed_block: fields.field()?,
            kzg_proofs: fields.field()?,
            blobs: fields.field()?,
        })
    }
}

/// An unsigned block with every blob it commits to and their proofs.
///
/// This is the Fulu body of the produce-block route in the beacon API, not a consensus container.
/// See `BlockContents` in the beacon-APIs repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockContents<P: Preset> {
    /// The block, before its proposer signs it.
    pub block: BeaconBlock<P>,

    /// Cell proofs of every extended blob, blob after blob.
    pub kzg_proofs: List<KzgProof, P::MaxCellProofsPerBlock>,

    /// The blobs, in commitment order.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for BlockContents<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <BeaconBlock<P>>::FIXED_SIZE,
        <List<KzgProof, P::MaxCellProofsPerBlock>>::FIXED_SIZE,
        <List<Blob<P>, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block);
        visitor.field(&self.kzg_proofs);
        visitor.field(&self.blobs);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block: fields.field()?,
            kzg_proofs: fields.field()?,
            blobs: fields.field()?,
        })
    }
}

impl<P: Preset> BlockContents<P> {
    /// The signed contents, once the proposer has signed the block.
    #[must_use]
    pub fn sign(self, signature: BlsSignature) -> SignedBlockContents<P> {
        SignedBlockContents {
            signed_block: SignedBeaconBlock {
                message: self.block,
                signature,
            },
            kzg_proofs: self.kzg_proofs,
            blobs: self.blobs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Minimal, Slot};

    #[test]
    fn contents_round_trip_through_ssz() {
        // Fixture state: a block at slot 3 with one blob and its 128 cell proofs.
        let mut contents = SignedBlockContents::<Minimal>::default();
        contents.signed_block.message.slot = Slot(3);
        contents.blobs.push(Blob::<Minimal>::default()).unwrap();
        for _ in 0..128 {
            contents.kzg_proofs.push(KzgProof::default()).unwrap();
        }

        let decoded = SignedBlockContents::<Minimal>::decode(&contents.encode()).unwrap();

        assert_eq!(decoded, contents);
    }
}
