//! A block bundled with its blobs, the unit a proposer publishes.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    BlsSignature, KzgProof, Preset,
    electra::{BeaconBlock, Blob, SignedBeaconBlock},
};

/// A signed block with every blob it commits to and one proof per blob.
///
/// Electra changes the block inside, so the bundle is a new container.
/// This is the Electra body of the publish-block route in the beacon API, not a consensus container.
/// See `SignedBlockContents` in the beacon-APIs repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBlockContents<P: Preset> {
    /// The block.
    pub signed_block: SignedBeaconBlock<P>,

    /// Proofs that open each commitment to its blob, in commitment order.
    pub kzg_proofs: List<KzgProof, P::MaxBlobCommitmentsPerBlock>,

    /// The blobs, in commitment order.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for SignedBlockContents<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <SignedBeaconBlock<P>>::FIXED_SIZE,
        <List<KzgProof, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
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
/// This is the Electra body of the produce-block route in the beacon API, not a consensus container.
/// See `BlockContents` in the beacon-APIs repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockContents<P: Preset> {
    /// The block, before its proposer signs it.
    pub block: BeaconBlock<P>,

    /// Proofs that open each commitment to its blob, in commitment order.
    pub kzg_proofs: List<KzgProof, P::MaxBlobCommitmentsPerBlock>,

    /// The blobs, in commitment order.
    pub blobs: List<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

impl<P: Preset> Container for BlockContents<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <BeaconBlock<P>>::FIXED_SIZE,
        <List<KzgProof, P::MaxBlobCommitmentsPerBlock>>::FIXED_SIZE,
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
        // Fixture state: a block at slot 3 with two blobs and their two proofs.
        let mut contents = SignedBlockContents::<Minimal>::default();
        contents.signed_block.message.slot = Slot(3);
        for byte in [1, 2] {
            contents.blobs.push(Blob::<Minimal>::default()).unwrap();
            contents.kzg_proofs.push(KzgProof([byte; 48])).unwrap();
        }

        let decoded = SignedBlockContents::<Minimal>::decode(&contents.encode()).unwrap();

        assert_eq!(decoded, contents);
    }
}
