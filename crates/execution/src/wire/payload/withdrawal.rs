//! WithdrawalV1, defined in `src/engine/shanghai.md`.
//!
//! ```text
//!     index            QUANTITY 64
//!     validatorIndex   QUANTITY 64
//!     address          DATA 20
//!     amount           QUANTITY 64, in Gwei
//! ```

use axiom_json::Json;
use axiom_types::capella::Withdrawal;

use crate::{
    WireError,
    wire::{Fields, JsonCodec},
};

impl JsonCodec for Withdrawal {
    /// WithdrawalV1: the amount stays in Gwei, as the consensus layer counts it.
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("validatorIndex", self.validator_index.to_json()),
            ("address", self.address.to_json()),
            ("amount", self.amount.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            validator_index: fields.required("validatorIndex")?,
            address: fields.required("address")?,
            amount: fields.required("amount")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ExecutionAddress, Gwei, ValidatorIndex, WithdrawalIndex};

    use super::*;

    #[test]
    fn amount_travels_in_gwei() {
        // 32 ETH is 32_000_000_000 Gwei, "0x773594000"; validator 300 is "0x12c".
        let withdrawal = Withdrawal {
            index: WithdrawalIndex(7),
            validator_index: ValidatorIndex(300),
            address: ExecutionAddress([0xaa; 20]),
            amount: Gwei(32_000_000_000),
        };
        let expected = Json::parse(format!(
            r#"{{"index":"0x7","validatorIndex":"0x12c","address":"0x{}","amount":"0x773594000"}}"#,
            "aa".repeat(20)
        ))
        .unwrap();
        assert_eq!(withdrawal.to_json(), expected);
        assert_eq!(Withdrawal::from_json(&expected), Ok(withdrawal));
    }
}
