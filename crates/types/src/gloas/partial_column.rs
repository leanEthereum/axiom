//! Partial data columns of Gloas, which drop the header now that sidecars name their block.
//!
//! See the Gloas partial columns networking spec.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, ProgressiveBitList, Ssz};

use crate::{
    Preset, Root, Slot,
    gloas::{DataColumn, KzgProofs},
};

/// One bit per blob of a block.
pub type CellsBitList = ProgressiveBitList;

/// The cells of one column a peer holds, with their proofs.
///
/// The column index comes from the gossip topic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnSidecar<P: Preset> {
    /// Which blobs' cells are present.
    pub cells_present_bitmap: CellsBitList,

    /// The present cells, in blob order.
    pub partial_column: DataColumn<P>,

    /// Proofs of the present cells.
    pub kzg_proofs: KzgProofs,
}

impl<P: Preset> Container for PartialDataColumnSidecar<P> {
    const FIELDS: &'static [Option<usize>] = &[
        CellsBitList::FIXED_SIZE,
        <DataColumn<P>>::FIXED_SIZE,
        KzgProofs::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.cells_present_bitmap);
        visitor.field(&self.partial_column);
        visitor.field(&self.kzg_proofs);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            cells_present_bitmap: fields.field()?,
            partial_column: fields.field()?,
            kzg_proofs: fields.field()?,
        })
    }
}

/// Which cells of a column a peer has, and which it wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnPartsMetadata {
    /// Cells the peer holds and will provide.
    pub available: CellsBitList,

    /// Cells the peer asks for.
    pub requests: CellsBitList,
}

impl Container for PartialDataColumnPartsMetadata {
    const FIELDS: &'static [Option<usize>] = &[CellsBitList::FIXED_SIZE, CellsBitList::FIXED_SIZE];

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

/// Names the block a group of partial columns belongs to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialDataColumnGroupId {
    /// Root of the block.
    pub beacon_block_root: Root,

    /// Slot of the block.
    pub slot: Slot,
}

impl Container for PartialDataColumnGroupId {
    const FIELDS: &'static [Option<usize>] = &[Root::FIXED_SIZE, Slot::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.beacon_block_root);
        visitor.field(&self.slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            beacon_block_root: fields.field()?,
            slot: fields.field()?,
        })
    }
}
