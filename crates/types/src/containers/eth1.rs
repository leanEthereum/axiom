//! Data about the execution chain, as votes and as the merge-era proof-of-work block.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, U256};

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
