//! A proposer's fee recipient and gas target for its slot, from the Gloas validator spec.

use axiom_json::Json;
use axiom_types::gloas::{ProposerPreferences, SignedProposerPreferences};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for ProposerPreferences {
    fn to_json(&self) -> Json {
        Json::from([
            ("dependent_root", self.dependent_root.to_json()),
            ("proposal_slot", self.proposal_slot.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("fee_recipient", self.fee_recipient.to_json()),
            ("target_gas_limit", self.target_gas_limit.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            dependent_root: fields.required("dependent_root")?,
            proposal_slot: fields.required("proposal_slot")?,
            validator_index: fields.required("validator_index")?,
            fee_recipient: fields.required("fee_recipient")?,
            target_gas_limit: fields.required("target_gas_limit")?,
        })
    }
}

impl ApiJson for SignedProposerPreferences {
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

    impl Sample for ProposerPreferences {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                dependent_root: sampler.draw(),
                proposal_slot: sampler.draw(),
                validator_index: sampler.draw(),
                fee_recipient: sampler.draw(),
                target_gas_limit: sampler.draw(),
            }
        }
    }

    impl Sample for SignedProposerPreferences {
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
        fn preferences_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<ProposerPreferences>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedProposerPreferences>().map_err(TestCaseError::fail)?;
        }
    }
}
