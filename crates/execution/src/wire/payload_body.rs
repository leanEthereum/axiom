//! ExecutionPayloadBodyV1, the part of a payload its header does not hold.
//!
//! Defined in `src/engine/shanghai.md`.
//!
//! ```text
//!     transactions   Array of DATA, each an EIP-2718 transaction
//!     withdrawals    Array of WithdrawalV1, or null before Shanghai
//! ```

use axiom_json::Json;
use axiom_types::capella::Withdrawal;

use super::{Fields, JsonCodec, Reader};
use crate::WireError;

/// A payload's transactions and withdrawals, by which the engine returns a payload it executed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadBody {
    /// The transactions, in block order.
    pub transactions: Vec<Vec<u8>>,
    /// The withdrawals, none before Shanghai.
    pub withdrawals: Option<Vec<Withdrawal>>,
}

impl JsonCodec for PayloadBody {
    fn to_json(&self) -> Json {
        let transactions = self.transactions.iter().map(JsonCodec::to_json).collect();
        let withdrawals = self.withdrawals.as_ref().map_or(Json::Null, |withdrawals| {
            Json::Array(withdrawals.iter().map(JsonCodec::to_json).collect())
        });
        Json::from([
            ("transactions", Json::Array(transactions)),
            ("withdrawals", withdrawals),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        let transactions = fields.required::<Transactions>("transactions")?.0;
        let withdrawals = fields
            .optional::<Withdrawals>("withdrawals")?
            .map(|withdrawals| withdrawals.0);
        Ok(Self {
            transactions,
            withdrawals,
        })
    }
}

/// The transactions member: an array of DATA.
struct Transactions(Vec<Vec<u8>>);

impl JsonCodec for Transactions {
    fn to_json(&self) -> Json {
        Json::Array(self.0.iter().map(JsonCodec::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        Reader::new(value).items()?.decode().map(Self)
    }
}

/// The withdrawals member: an array of WithdrawalV1.
struct Withdrawals(Vec<Withdrawal>);

impl JsonCodec for Withdrawals {
    fn to_json(&self) -> Json {
        Json::Array(self.0.iter().map(JsonCodec::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        Reader::new(value).items()?.decode().map(Self)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ExecutionAddress, Gwei, ValidatorIndex, WithdrawalIndex};

    use super::*;

    #[test]
    fn bodies_round_trip_with_and_without_withdrawals() {
        // A Shanghai body: one two-byte transaction and one withdrawal of 5 Gwei.
        let text = r#"{"transactions":["0x02f8"],"withdrawals":[{"index":"0x1","validatorIndex":"0x2","address":"0x0000000000000000000000000000000000000003","amount":"0x5"}]}"#;
        let body = PayloadBody::from_json(&Json::parse(text).unwrap()).unwrap();
        assert_eq!(
            body,
            PayloadBody {
                transactions: vec![vec![0x02, 0xf8]],
                withdrawals: Some(vec![Withdrawal {
                    index: WithdrawalIndex(1),
                    validator_index: ValidatorIndex(2),
                    address: ExecutionAddress({
                        let mut address = [0; 20];
                        address[19] = 3;
                        address
                    }),
                    amount: Gwei(5),
                }]),
            }
        );
        assert_eq!(PayloadBody::from_json(&body.to_json()), Ok(body));

        // Before Shanghai the withdrawals are null.
        let merge = r#"{"transactions":[],"withdrawals":null}"#;
        assert_eq!(
            PayloadBody::from_json(&Json::parse(merge).unwrap()),
            Ok(PayloadBody::default())
        );
    }
}
