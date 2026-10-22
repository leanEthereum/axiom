//! Data column sidecars, the unit of PeerDAS sampling.

use axiom_ssz::{
    ByteVector, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, Vector,
};

use crate::{
    Bytes32, ColumnIndex, KzgProof, Preset, Root,
    fulu::{BlobKzgCommitments, SignedBeaconBlockHeader},
};

/// A cell: 64 field elements of an extended blob.
pub type Cell<P> = ByteVector<<P as Preset>::BytesPerCell>;

/// One cell from each blob of a block.
pub type DataColumn<P> = List<Cell<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// One proof per cell of a column.
pub type KzgProofs<P> = List<KzgProof, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// Branch from the commitment list to the body root.
pub type KzgCommitmentsInclusionProof<P> =
    Vector<Bytes32, <P as Preset>::KzgCommitmentsInclusionProofDepth>;

/// One column of the extended blob matrix, with proofs.
///
/// See EIP-7594.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataColumnSidecar<P: Preset> {
    /// Column position.
    pub index: ColumnIndex,

    /// The cells, one per blob.
    pub column: DataColumn<P>,

    /// Commitments to the block's blobs.
    pub kzg_commitments: BlobKzgCommitments<P>,

    /// Proofs, one per cell.
    pub kzg_proofs: KzgProofs<P>,

    /// Header of the block.
    pub signed_block_header: SignedBeaconBlockHeader,

    /// Branch from the commitments to the body root.
    pub kzg_commitments_inclusion_proof: KzgCommitmentsInclusionProof<P>,
}

impl<P: Preset> Container for DataColumnSidecar<P> {
    const FIELDS: &'static [Option<usize>] = &[
        ColumnIndex::FIXED_SIZE,
        <DataColumn<P>>::FIXED_SIZE,
        <BlobKzgCommitments<P>>::FIXED_SIZE,
        <KzgProofs<P>>::FIXED_SIZE,
        SignedBeaconBlockHeader::FIXED_SIZE,
        <KzgCommitmentsInclusionProof<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.index);
        visitor.field(&self.column);
        visitor.field(&self.kzg_commitments);
        visitor.field(&self.kzg_proofs);
        visitor.field(&self.signed_block_header);
        visitor.field(&self.kzg_commitments_inclusion_proof);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: fields.field()?,
            column: fields.field()?,
            kzg_commitments: fields.field()?,
            kzg_proofs: fields.field()?,
            signed_block_header: fields.field()?,
            kzg_commitments_inclusion_proof: fields.field()?,
        })
    }
}

/// Names some columns of one block, for a request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataColumnsByRootIdentifier<P: Preset> {
    /// Block the columns belong to.
    pub block_root: Root,

    /// Requested column positions.
    pub columns: List<ColumnIndex, P::NumberOfColumns>,
}

impl<P: Preset> Container for DataColumnsByRootIdentifier<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Root::FIXED_SIZE,
        <List<ColumnIndex, P::NumberOfColumns>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block_root);
        visitor.field(&self.columns);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block_root: fields.field()?,
            columns: fields.field()?,
        })
    }
}

/// One cell of the extended blob matrix, with its proof and position.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatrixEntry<P: Preset> {
    /// The cell.
    pub cell: Cell<P>,

    /// Proof the cell matches its blob's commitment.
    pub kzg_proof: KzgProof,

    /// Column of the cell.
    pub column_index: ColumnIndex,

    /// Row of the cell, the blob position.
    pub row_index: u64,
}

impl<P: Preset> Container for MatrixEntry<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <Cell<P>>::FIXED_SIZE,
        KzgProof::FIXED_SIZE,
        ColumnIndex::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.cell);
        visitor.field(&self.kzg_proof);
        visitor.field(&self.column_index);
        visitor.field(&self.row_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            cell: fields.field()?,
            kzg_proof: fields.field()?,
            column_index: fields.field()?,
            row_index: fields.field()?,
        })
    }
}
