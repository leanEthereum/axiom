//! Data column sidecars of Gloas, which name their block instead of carrying its header.
//!
//! The commitments live in the block's bid, so no inclusion proof is needed.
//! See the Gloas networking spec.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, ProgressiveList, Ssz};

use crate::{ColumnIndex, KzgProof, Preset, Root, Slot, gloas::Cell};

/// One cell from each blob of a block.
pub type DataColumn<P> = ProgressiveList<Cell<P>>;

/// One proof per cell of a column.
pub type KzgProofs = ProgressiveList<KzgProof>;

/// One column of the extended blob matrix, with proofs.
///
/// See EIP-7594 and EIP-7732.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataColumnSidecar<P: Preset> {
    /// Column position.
    pub index: ColumnIndex,

    /// The cells, one per blob.
    pub column: DataColumn<P>,

    /// Proofs, one per cell.
    pub kzg_proofs: KzgProofs,

    /// Slot of the block.
    pub slot: Slot,

    /// Root of the block whose bid commits to the blobs.
    pub beacon_block_root: Root,
}

impl<P: Preset> Container for DataColumnSidecar<P> {
    const FIELDS: &'static [Option<usize>] = &[
        ColumnIndex::FIXED_SIZE,
        <DataColumn<P>>::FIXED_SIZE,
        KzgProofs::FIXED_SIZE,
        Slot::FIXED_SIZE,
        Root::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.index);
        visitor.field(&self.column);
        visitor.field(&self.kzg_proofs);
        visitor.field(&self.slot);
        visitor.field(&self.beacon_block_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: fields.field()?,
            column: fields.field()?,
            kzg_proofs: fields.field()?,
            slot: fields.field()?,
            beacon_block_root: fields.field()?,
        })
    }
}
