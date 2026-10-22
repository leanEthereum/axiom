//! Data about the execution chain, as the deposit votes see it.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{Hash32, Root};

/// A snapshot of the deposit contract, voted into the state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Eth1Data {
    /// Root of the deposit contract tree.
    pub deposit_root: Root,

    /// Number of deposits in the tree.
    pub deposit_count: u64,

    /// Execution block the snapshot was taken at.
    pub block_hash: Hash32,
}

impl Container for Eth1Data {
    const FIELDS: &'static [Option<usize>] =
        &[Root::FIXED_SIZE, u64::FIXED_SIZE, Hash32::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.deposit_root);
        visitor.field(&self.deposit_count);
        visitor.field(&self.block_hash);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            deposit_root: fields.field()?,
            deposit_count: fields.field()?,
            block_hash: fields.field()?,
        })
    }
}

/// The fields of an execution block that deposit voting reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Eth1Block {
    /// Block timestamp.
    pub timestamp: u64,

    /// Root of the deposit contract tree.
    pub deposit_root: Root,

    /// Number of deposits in the tree.
    pub deposit_count: u64,
}

impl Container for Eth1Block {
    const FIELDS: &'static [Option<usize>] = &[u64::FIXED_SIZE, Root::FIXED_SIZE, u64::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.timestamp);
        visitor.field(&self.deposit_root);
        visitor.field(&self.deposit_count);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            timestamp: fields.field()?,
            deposit_root: fields.field()?,
            deposit_count: fields.field()?,
        })
    }
}
