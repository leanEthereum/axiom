//! Execution layer requests, see EIP-6110, EIP-7002, EIP-7251, and EIP-7685.

use axiom_json::Json;
use axiom_types::{
    Preset,
    electra::{ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for DepositRequest {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            (
                "withdrawal_credentials",
                self.withdrawal_credentials.to_json(),
            ),
            ("amount", self.amount.to_json()),
            ("signature", self.signature.to_json()),
            ("index", self.index.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            withdrawal_credentials: fields.required("withdrawal_credentials")?,
            amount: fields.required("amount")?,
            signature: fields.required("signature")?,
            index: fields.required("index")?,
        })
    }
}

impl ApiJson for WithdrawalRequest {
    fn to_json(&self) -> Json {
        Json::from([
            ("source_address", self.source_address.to_json()),
            ("validator_pubkey", self.validator_pubkey.to_json()),
            ("amount", self.amount.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            source_address: fields.required("source_address")?,
            validator_pubkey: fields.required("validator_pubkey")?,
            amount: fields.required("amount")?,
        })
    }
}

impl ApiJson for ConsolidationRequest {
    fn to_json(&self) -> Json {
        Json::from([
            ("source_address", self.source_address.to_json()),
            ("source_pubkey", self.source_pubkey.to_json()),
            ("target_pubkey", self.target_pubkey.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            source_address: fields.required("source_address")?,
            source_pubkey: fields.required("source_pubkey")?,
            target_pubkey: fields.required("target_pubkey")?,
        })
    }
}

impl<P: Preset> ApiJson for ExecutionRequests<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("deposits", self.deposits.to_json()),
            ("withdrawals", self.withdrawals.to_json()),
            ("consolidations", self.consolidations.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            deposits: fields.required("deposits")?,
            withdrawals: fields.required("withdrawals")?,
            consolidations: fields.required("consolidations")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for DepositRequest {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                pubkey: sampler.draw(),
                withdrawal_credentials: sampler.draw(),
                amount: sampler.draw(),
                signature: sampler.draw(),
                index: sampler.draw(),
            }
        }
    }

    impl Sample for WithdrawalRequest {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                source_address: sampler.draw(),
                validator_pubkey: sampler.draw(),
                amount: sampler.draw(),
            }
        }
    }

    impl Sample for ConsolidationRequest {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                source_address: sampler.draw(),
                source_pubkey: sampler.draw(),
                target_pubkey: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for ExecutionRequests<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                deposits: sampler.draw(),
                withdrawals: sampler.draw(),
                consolidations: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn requests_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<DepositRequest>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<WithdrawalRequest>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ConsolidationRequest>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ExecutionRequests<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
