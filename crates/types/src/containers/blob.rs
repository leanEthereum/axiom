//! Blob sidecars, the EIP-4844 data carried beside a block.

use axiom_ssz::{ByteVector, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, Vector};

use crate::{BlobIndex, Bytes32, KzgCommitment, KzgProof, Preset, Root, SignedBeaconBlockHeader};

/// A blob: 4096 field elements of 32 bytes each.
pub type Blob<P> = ByteVector<<P as Preset>::BytesPerBlob>;

/// Names one blob of one block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobIdentifier {
    /// Block the blob belongs to.
    pub block_root: Root,

    /// Position of the blob.
    pub index: BlobIndex,
}

impl Container for BlobIdentifier {
    const FIELDS: &'static [Option<usize>] = &[Root::FIXED_SIZE, BlobIndex::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block_root);
        visitor.field(&self.index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block_root: fields.field()?,
            index: fields.field()?,
        })
    }
}

/// A blob with its commitment, opening proof, and proof of inclusion in a block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobSidecar<P: Preset> {
    /// Position of the blob.
    pub index: BlobIndex,

    /// The blob.
    pub blob: Blob<P>,

    /// Commitment to the blob.
    pub kzg_commitment: KzgCommitment,

    /// Proof the blob matches the commitment.
    pub kzg_proof: KzgProof,

    /// Header of the block.
    pub signed_block_header: SignedBeaconBlockHeader,

    /// Branch from the commitment to the body root.
    pub kzg_commitment_inclusion_proof: Vector<Bytes32, P::KzgCommitmentInclusionProofDepth>,
}

impl<P: Preset> Container for BlobSidecar<P> {
    const FIELDS: &'static [Option<usize>] = &[
        BlobIndex::FIXED_SIZE,
        <Blob<P>>::FIXED_SIZE,
        KzgCommitment::FIXED_SIZE,
        KzgProof::FIXED_SIZE,
        SignedBeaconBlockHeader::FIXED_SIZE,
        <Vector<Bytes32, P::KzgCommitmentInclusionProofDepth>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.index);
        visitor.field(&self.blob);
        visitor.field(&self.kzg_commitment);
        visitor.field(&self.kzg_proof);
        visitor.field(&self.signed_block_header);
        visitor.field(&self.kzg_commitment_inclusion_proof);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: fields.field()?,
            blob: fields.field()?,
            kzg_commitment: fields.field()?,
            kzg_proof: fields.field()?,
            signed_block_header: fields.field()?,
            kzg_commitment_inclusion_proof: fields.field()?,
        })
    }
}
