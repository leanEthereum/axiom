//! Changes of withdrawal credentials to an execution address, from the Capella beacon chain spec.

use axiom_json::Json;
use axiom_types::capella::{BlsToExecutionChange, SignedBlsToExecutionChange};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for BlsToExecutionChange {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("from_bls_pubkey", self.from_bls_pubkey.to_json()),
            ("to_execution_address", self.to_execution_address.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            from_bls_pubkey: fields.required("from_bls_pubkey")?,
            to_execution_address: fields.required("to_execution_address")?,
        })
    }
}

impl ApiJson for SignedBlsToExecutionChange {
    fn to_json(&self) -> Json {
        Json::from([
            ("message", self.message.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            message: fields.required("message")?,
            signature: fields.required("signature")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for BlsToExecutionChange {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                validator_index: sampler.draw(),
                from_bls_pubkey: sampler.draw(),
                to_execution_address: sampler.draw(),
            }
        }
    }

    impl Sample for SignedBlsToExecutionChange {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn credential_changes_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BlsToExecutionChange>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBlsToExecutionChange>().map_err(TestCaseError::fail)?;
        }
    }
}
