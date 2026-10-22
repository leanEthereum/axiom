//! The Electra builder bid, which adds execution requests; Fulu keeps it.

use axiom_json::Json;
use axiom_types::{
    Preset,
    electra::{BuilderBid, SignedBuilderBid},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BuilderBid<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("header", self.header.to_json()),
            ("blob_kzg_commitments", self.blob_kzg_commitments.to_json()),
            ("execution_requests", self.execution_requests.to_json()),
            ("value", self.value.to_json()),
            ("pubkey", self.pubkey.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            header: fields.required("header")?,
            blob_kzg_commitments: fields.required("blob_kzg_commitments")?,
            execution_requests: fields.required("execution_requests")?,
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

    impl<P: Preset> Sample for BuilderBid<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                header: sampler.draw(),
                blob_kzg_commitments: sampler.draw(),
                execution_requests: sampler.draw(),
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
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn bids_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BuilderBid<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBuilderBid<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
