//! Messages of the builder API, through which a proposer buys an execution payload.
//!
//! These are not consensus containers.
//! Builder API messages are signed in the application builder domain, not in a fork's domain.
//! See the Bellatrix builder spec in the builder-specs repository.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsPubkey, BlsSignature, ExecutionAddress};

/// A validator's standing preferences for the payloads built on its behalf.
///
/// See `ValidatorRegistrationV1` in the Bellatrix builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorRegistrationV1 {
    /// Address that receives the payload's fees.
    pub fee_recipient: ExecutionAddress,

    /// Gas limit the validator asks builders to target.
    pub gas_limit: u64,

    /// Unix time of the registration, so a newer one replaces an older one.
    pub timestamp: u64,

    /// The registering validator.
    pub pubkey: BlsPubkey,
}

impl Container for ValidatorRegistrationV1 {
    const FIELDS: &'static [Option<usize>] = &[
        ExecutionAddress::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.fee_recipient);
        visitor.field(&self.gas_limit);
        visitor.field(&self.timestamp);
        visitor.field(&self.pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fee_recipient: fields.field()?,
            gas_limit: fields.field()?,
            timestamp: fields.field()?,
            pubkey: fields.field()?,
        })
    }
}

/// A registration with its validator's signature.
///
/// See `SignedValidatorRegistrationV1` in the Bellatrix builder spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedValidatorRegistrationV1 {
    /// The registration.
    pub message: ValidatorRegistrationV1,

    /// Validator's signature in the application builder domain.
    pub signature: BlsSignature,
}

impl Container for SignedValidatorRegistrationV1 {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorRegistrationV1::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

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
