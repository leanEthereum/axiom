//! Block headers, a block with its body replaced by the body root.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsSignature, Root, Slot, ValidatorIndex};

/// A block with its body replaced by the body's root.
///
/// It hashes to the same root as the full block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    /// Slot the block was proposed in.
    pub slot: Slot,

    /// Validator that proposed the block.
    pub proposer_index: ValidatorIndex,

    /// Root of the parent block.
    pub parent_root: Root,

    /// Root of the post-state.
    pub state_root: Root,

    /// Root of the block body.
    pub body_root: Root,
}

impl Container for BeaconBlockHeader {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        Root::FIXED_SIZE,
        Root::FIXED_SIZE,
        Root::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.proposer_index);
        visitor.field(&self.parent_root);
        visitor.field(&self.state_root);
        visitor.field(&self.body_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            proposer_index: fields.field()?,
            parent_root: fields.field()?,
            state_root: fields.field()?,
            body_root: fields.field()?,
        })
    }
}

/// A block header with its proposer's signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBeaconBlockHeader {
    /// The header.
    pub message: BeaconBlockHeader,

    /// Proposer's signature over the header.
    pub signature: BlsSignature,
}

impl Container for SignedBeaconBlockHeader {
    const FIELDS: &'static [Option<usize>] =
        &[BeaconBlockHeader::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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
