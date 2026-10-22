//! Validator registrations and builder bids, from the Bellatrix builder spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    bellatrix::{
        BuilderBid, SignedBuilderBid, SignedValidatorRegistrationV1, ValidatorRegistrationV1,
    },
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for ValidatorRegistrationV1 {
    fn to_json(&self) -> Json {
        Json::from([
            ("fee_recipient", self.fee_recipient.to_json()),
            ("gas_limit", self.gas_limit.to_json()),
            ("timestamp", self.timestamp.to_json()),
            ("pubkey", self.pubkey.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            fee_recipient: fields.required("fee_recipient")?,
            gas_limit: fields.required("gas_limit")?,
            timestamp: fields.required("timestamp")?,
            pubkey: fields.required("pubkey")?,
        })
    }
}

impl ApiJson for SignedValidatorRegistrationV1 {
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

impl<P: Preset> ApiJson for BuilderBid<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("header", self.header.to_json()),
            ("value", self.value.to_json()),
            ("pubkey", self.pubkey.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            header: fields.required("header")?,
            value: fields.required("value")?,
            pubkey: fields.required("pubkey")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedBuilderBid<P> {
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
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for ValidatorRegistrationV1 {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                fee_recipient: sampler.draw(),
                gas_limit: sampler.draw(),
                timestamp: sampler.draw(),
                pubkey: sampler.draw(),
            }
        }
    }

    impl Sample for SignedValidatorRegistrationV1 {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for BuilderBid<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                header: sampler.draw(),
                value: sampler.draw(),
                pubkey: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SignedBuilderBid<P> {
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
        fn builder_messages_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<ValidatorRegistrationV1>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedValidatorRegistrationV1>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<BuilderBid<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBuilderBid<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
