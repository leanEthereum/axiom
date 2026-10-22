//! Partial data columns, which let peers exchange the cells they hold.

use axiom_ssz::{BitList, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    Preset, Root,
    fulu::{
        BlobKzgCommitments, DataColumn, KzgCommitmentsInclusionProof, KzgProofs,
        SignedBeaconBlockHeader,
    },
};

/// One bit per blob of a block.
pub type CellsBitList<P> = BitList<<P as Preset>::MaxBlobCommitmentsPerBlock>;

/// The block a group of partial columns belongs to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnGroupId {
    /// The block.
    pub beacon_block_root: Root,
}

impl Container for PartialDataColumnGroupId {
    const FIELDS: &'static [Option<usize>] = &[Root::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.beacon_block_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            beacon_block_root: fields.field()?,
        })
    }
}

/// The block-level data shared by every partial column.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnHeader<P: Preset> {
    /// Commitments to the block's blobs.
    pub kzg_commitments: BlobKzgCommitments<P>,

    /// Header of the block.
    pub signed_block_header: SignedBeaconBlockHeader,

    /// Branch from the commitments to the body root.
    pub kzg_commitments_inclusion_proof: KzgCommitmentsInclusionProof<P>,
}

impl<P: Preset> Container for PartialDataColumnHeader<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <BlobKzgCommitments<P>>::FIXED_SIZE,
        SignedBeaconBlockHeader::FIXED_SIZE,
        <KzgCommitmentsInclusionProof<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.kzg_commitments);
        visitor.field(&self.signed_block_header);
        visitor.field(&self.kzg_commitments_inclusion_proof);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            kzg_commitments: fields.field()?,
            signed_block_header: fields.field()?,
            kzg_commitments_inclusion_proof: fields.field()?,
        })
    }
}

/// Which cells of a column a peer holds and wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnPartsMetadata<P: Preset> {
    /// Cells the peer holds.
    pub available: CellsBitList<P>,

    /// Cells the peer wants.
    pub requests: CellsBitList<P>,
}

impl<P: Preset> Container for PartialDataColumnPartsMetadata<P> {
    const FIELDS: &'static [Option<usize>] =
        &[<CellsBitList<P>>::FIXED_SIZE, <CellsBitList<P>>::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.available);
        visitor.field(&self.requests);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            available: fields.field()?,
            requests: fields.field()?,
        })
    }
}

/// Some cells of a column, with their proofs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnSidecar<P: Preset> {
    /// Which cells are present.
    pub cells_present_bitmap: CellsBitList<P>,

    /// The present cells, in order.
    pub partial_column: DataColumn<P>,

    /// Proofs of the present cells.
    pub kzg_proofs: KzgProofs<P>,

    /// The header, sent only on eager pushes.
    pub header: List<PartialDataColumnHeader<P>, Const<1>>,
}

impl<P: Preset> Container for PartialDataColumnSidecar<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <CellsBitList<P>>::FIXED_SIZE,
        <DataColumn<P>>::FIXED_SIZE,
        <KzgProofs<P>>::FIXED_SIZE,
        <List<PartialDataColumnHeader<P>, Const<1>>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.cells_present_bitmap);
        visitor.field(&self.partial_column);
        visitor.field(&self.kzg_proofs);
        visitor.field(&self.header);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            cells_present_bitmap: fields.field()?,
            partial_column: fields.field()?,
            kzg_proofs: fields.field()?,
            header: fields.field()?,
        })
    }
}
