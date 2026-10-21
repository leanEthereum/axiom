//! Checkpoints, the epoch boundary blocks that Casper FFG justifies and finalizes.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{Epoch, Root};

/// An epoch paired with the block root at its first slot.
///
/// Finality is decided on checkpoints rather than on every block.
/// See the Gasper paper, section 4.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checkpoint {
    /// Epoch the checkpoint belongs to.
    pub epoch: Epoch,

    /// Root of the block at the start of that epoch, or the latest block before it.
    pub root: Root,
}

impl Container for Checkpoint {
    const FIELDS: &'static [Option<usize>] = &[Epoch::FIXED_SIZE, Root::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.epoch);
        visitor.field(&self.root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            epoch: fields.field()?,
            root: fields.field()?,
        })
    }
}
