//! The envelope that reveals a payload after its block, from the Gloas beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    gloas::{ExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for ExecutionPayloadEnvelope<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("payload", self.payload.to_json()),
            ("execution_requests", self.execution_requests.to_json()),
            ("builder_index", self.builder_index.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            (
                "parent_beacon_block_root",
                self.parent_beacon_block_root.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            payload: fields.required("payload")?,
            execution_requests: fields.required("execution_requests")?,
            builder_index: fields.required("builder_index")?,
            beacon_block_root: fields.required("beacon_block_root")?,
            parent_beacon_block_root: fields.required("parent_beacon_block_root")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedExecutionPayloadEnvelope<P> {
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

    impl<P: Preset> Sample for ExecutionPayloadEnvelope<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                payload: sampler.draw(),
                execution_requests: sampler.draw(),
                builder_index: sampler.draw(),
                beacon_block_root: sampler.draw(),
                parent_beacon_block_root: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SignedExecutionPayloadEnvelope<P> {
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
        fn envelopes_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<ExecutionPayloadEnvelope<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedExecutionPayloadEnvelope<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
