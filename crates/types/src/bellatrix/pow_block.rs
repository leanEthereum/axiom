//! The proof-of-work block, as the merge transition reads it.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, U256};

use crate::Hash32;

/// A proof-of-work block, as the merge transition reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PowBlock {
    /// Block hash.
    pub block_hash: Hash32,

    /// Parent block hash.
    pub parent_hash: Hash32,

    /// Cumulative difficulty up to this block.
    pub total_difficulty: U256,
}

impl Container for PowBlock {
    const FIELDS: &'static [Option<usize>] =
        &[Hash32::FIXED_SIZE, Hash32::FIXED_SIZE, U256::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.block_hash);
        visitor.field(&self.parent_hash);
        visitor.field(&self.total_difficulty);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            block_hash: fields.field()?,
            parent_hash: fields.field()?,
            total_difficulty: fields.field()?,
        })
    }
}
