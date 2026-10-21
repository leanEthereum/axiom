//! Voluntary exits.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsSignature, Epoch, ValidatorIndex};

/// A validator's request to stop validating.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VoluntaryExit {
    /// Earliest epoch the exit may be processed.
    pub epoch: Epoch,

    /// The exiting validator.
    pub validator_index: ValidatorIndex,
}

impl Container for VoluntaryExit {
    const FIELDS: &'static [Option<usize>] = &[Epoch::FIXED_SIZE, ValidatorIndex::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.epoch);
        visitor.field(&self.validator_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            epoch: fields.field()?,
            validator_index: fields.field()?,
        })
    }
}

/// A voluntary exit signed by the exiting validator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedVoluntaryExit {
    /// The exit.
    pub message: VoluntaryExit,

    /// Validator's signature.
    pub signature: BlsSignature,
}

impl Container for SignedVoluntaryExit {
    const FIELDS: &'static [Option<usize>] = &[VoluntaryExit::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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
