//! Changes from BLS withdrawal credentials to an execution address.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsPubkey, BlsSignature, ExecutionAddress, ValidatorIndex};

/// A one-time switch of withdrawal credentials to an execution address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlsToExecutionChange {
    /// Validator whose credentials change.
    pub validator_index: ValidatorIndex,

    /// Withdrawal key the old credentials commit to.
    pub from_bls_pubkey: BlsPubkey,

    /// New withdrawal address.
    pub to_execution_address: ExecutionAddress,
}

impl Container for BlsToExecutionChange {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorIndex::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.validator_index);
        visitor.field(&self.from_bls_pubkey);
        visitor.field(&self.to_execution_address);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            validator_index: fields.field()?,
            from_bls_pubkey: fields.field()?,
            to_execution_address: fields.field()?,
        })
    }
}

/// A credential change signed by the withdrawal key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedBlsToExecutionChange {
    /// The change.
    pub message: BlsToExecutionChange,

    /// Signature by the withdrawal key.
    pub signature: BlsSignature,
}

impl Container for SignedBlsToExecutionChange {
    const FIELDS: &'static [Option<usize>] =
        &[BlsToExecutionChange::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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
