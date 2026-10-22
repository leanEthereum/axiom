//! A validator's registry record, from the phase0 beacon chain spec.

use axiom_json::Json;
use axiom_types::phase0::Validator;

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for Validator {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            (
                "withdrawal_credentials",
                self.withdrawal_credentials.to_json(),
            ),
            ("effective_balance", self.effective_balance.to_json()),
            ("slashed", self.slashed.to_json()),
            (
                "activation_eligibility_epoch",
                self.activation_eligibility_epoch.to_json(),
            ),
            ("activation_epoch", self.activation_epoch.to_json()),
            ("exit_epoch", self.exit_epoch.to_json()),
            ("withdrawable_epoch", self.withdrawable_epoch.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            withdrawal_credentials: fields.required("withdrawal_credentials")?,
            effective_balance: fields.required("effective_balance")?,
            slashed: fields.required("slashed")?,
            activation_eligibility_epoch: fields.required("activation_eligibility_epoch")?,
            activation_epoch: fields.required("activation_epoch")?,
            exit_epoch: fields.required("exit_epoch")?,
            withdrawable_epoch: fields.required("withdrawable_epoch")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for Validator {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                pubkey: sampler.draw(),
                withdrawal_credentials: sampler.draw(),
                effective_balance: sampler.draw(),
                slashed: sampler.draw(),
                activation_eligibility_epoch: sampler.draw(),
                activation_epoch: sampler.draw(),
                exit_epoch: sampler.draw(),
                withdrawable_epoch: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn validator_round_trips(seed in any::<u64>()) {
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<Validator>().map_err(TestCaseError::fail)?;
        }
    }
}
