//! Proposer preferences, which tell builders what a proposer will accept.
//!
//! See the Gloas networking spec.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsSignature, ExecutionAddress, Root, Slot, ValidatorIndex};

/// What a proposer asks of the bids for one of its slots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposerPreferences {
    /// Block root the proposer duty was computed from.
    pub dependent_root: Root,

    /// Slot the preferences apply to.
    pub proposal_slot: Slot,

    /// The proposer.
    pub validator_index: ValidatorIndex,

    /// Address the payload's fees must go to.
    pub fee_recipient: ExecutionAddress,

    /// Gas limit the proposer wants the payload to move towards.
    pub target_gas_limit: u64,
}

impl Container for ProposerPreferences {
    const FIELDS: &'static [Option<usize>] = &[
        Root::FIXED_SIZE,
        Slot::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.dependent_root);
        visitor.field(&self.proposal_slot);
        visitor.field(&self.validator_index);
        visitor.field(&self.fee_recipient);
        visitor.field(&self.target_gas_limit);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            dependent_root: fields.field()?,
            proposal_slot: fields.field()?,
            validator_index: fields.field()?,
            fee_recipient: fields.field()?,
            target_gas_limit: fields.field()?,
        })
    }
}

/// Preferences with their proposer's signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedProposerPreferences {
    /// The preferences.
    pub message: ProposerPreferences,

    /// Proposer's signature.
    pub signature: BlsSignature,
}

impl Container for SignedProposerPreferences {
    const FIELDS: &'static [Option<usize>] =
        &[ProposerPreferences::FIXED_SIZE, BlsSignature::FIXED_SIZE];

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
