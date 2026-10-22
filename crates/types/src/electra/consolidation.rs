//! Consolidations, which merge one validator's stake into another.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsPubkey, ExecutionAddress, ValidatorIndex};

/// A consolidation triggered from the execution layer.
///
/// See EIP-7251.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConsolidationRequest {
    /// Address that sent the request, which must own the source credentials.
    pub source_address: ExecutionAddress,

    /// Validator whose stake moves.
    pub source_pubkey: BlsPubkey,

    /// Validator that receives the stake.
    pub target_pubkey: BlsPubkey,
}

impl Container for ConsolidationRequest {
    const FIELDS: &'static [Option<usize>] = &[
        ExecutionAddress::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.source_address);
        visitor.field(&self.source_pubkey);
        visitor.field(&self.target_pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            source_address: fields.field()?,
            source_pubkey: fields.field()?,
            target_pubkey: fields.field()?,
        })
    }
}

/// A consolidation waiting for its source to become withdrawable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingConsolidation {
    /// Validator whose stake moves.
    pub source_index: ValidatorIndex,

    /// Validator that receives the stake.
    pub target_index: ValidatorIndex,
}

impl Container for PendingConsolidation {
    const FIELDS: &'static [Option<usize>] =
        &[ValidatorIndex::FIXED_SIZE, ValidatorIndex::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.source_index);
        visitor.field(&self.target_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            source_index: fields.field()?,
            target_index: fields.field()?,
        })
    }
}
