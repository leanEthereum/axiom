//! Blob bundles with cell proofs, see EIP-7594 and the Fulu builder spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    fulu::{BlobsBundle, ExecutionPayloadAndBlobsBundle},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BlobsBundle<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("commitments", self.commitments.to_json()),
            ("proofs", self.proofs.to_json()),
            ("blobs", self.blobs.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            commitments: fields.required("commitments")?,
            proofs: fields.required("proofs")?,
            blobs: fields.required("blobs")?,
        })
    }
}

impl<P: Preset> ApiJson for ExecutionPayloadAndBlobsBundle<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("execution_payload", self.execution_payload.to_json()),
            ("blobs_bundle", self.blobs_bundle.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            execution_payload: fields.required("execution_payload")?,
            blobs_bundle: fields.required("blobs_bundle")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl<P: Preset> Sample for BlobsBundle<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                commitments: sampler.draw(),
                proofs: sampler.draw(),
                blobs: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for ExecutionPayloadAndBlobsBundle<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                execution_payload: sampler.draw(),
                blobs_bundle: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn blob_bundles_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BlobsBundle<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ExecutionPayloadAndBlobsBundle<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
