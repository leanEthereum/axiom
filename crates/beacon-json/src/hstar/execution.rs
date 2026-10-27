//! The Hstar execution requests, which add key authorizations, see EIP-8450.

use axiom_json::Json;
use axiom_types::hstar::ExecutionRequests;

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for ExecutionRequests {
    fn to_json(&self) -> Json {
        Json::from([
            ("deposits", self.deposits.to_json()),
            ("withdrawals", self.withdrawals.to_json()),
            ("consolidations", self.consolidations.to_json()),
            ("builder_deposits", self.builder_deposits.to_json()),
            ("builder_exits", self.builder_exits.to_json()),
            (
                "pq_key_authorizations",
                self.pq_key_authorizations.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            deposits: fields.required("deposits")?,
            withdrawals: fields.required("withdrawals")?,
            consolidations: fields.required("consolidations")?,
            builder_deposits: fields.required("builder_deposits")?,
            builder_exits: fields.required("builder_exits")?,
            pq_key_authorizations: fields.required("pq_key_authorizations")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for ExecutionRequests {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                deposits: sampler.draw(),
                withdrawals: sampler.draw(),
                consolidations: sampler.draw(),
                builder_deposits: sampler.draw(),
                builder_exits: sampler.draw(),
                pq_key_authorizations: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn requests_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<ExecutionRequests>().map_err(TestCaseError::fail)?;
        }
    }
}
