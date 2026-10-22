//! Withdrawals, which move ether from validator balances to execution addresses.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{ExecutionAddress, Gwei, ValidatorIndex, WithdrawalIndex};

/// A transfer of ether from a validator balance to an execution address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Withdrawal {
    /// Sequence number of the withdrawal.
    pub index: WithdrawalIndex,

    /// Validator the ether leaves.
    pub validator_index: ValidatorIndex,

    /// Address the ether goes to.
    pub address: ExecutionAddress,

    /// Amount withdrawn.
    pub amount: Gwei,
}

impl Container for Withdrawal {
    const FIELDS: &'static [Option<usize>] = &[
        WithdrawalIndex::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        Gwei::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.index);
        visitor.field(&self.validator_index);
        visitor.field(&self.address);
        visitor.field(&self.amount);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: fields.field()?,
            validator_index: fields.field()?,
            address: fields.field()?,
            amount: fields.field()?,
        })
    }
}
