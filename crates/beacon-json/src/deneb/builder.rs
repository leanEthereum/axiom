//! Blob bundles and builder bids, from the Deneb builder spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    deneb::{BlobsBundle, BuilderBid, ExecutionPayloadAndBlobsBundle, SignedBuilderBid},
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

impl<P: Preset> ApiJson for BuilderBid<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("header", self.header.to_json()),
            ("blob_kzg_commitments", self.blob_kzg_commitments.to_json()),
            ("value", self.value.to_json()),
            ("pubkey", self.pubkey.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            header: fields.required("header")?,
            blob_kzg_commitments: fields.required("blob_kzg_commitments")?,
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

    impl<P: Preset> Sample for BuilderBid<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                header: sampler.draw(),
                blob_kzg_commitments: sampler.draw(),
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
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn builder_messages_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BlobsBundle<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ExecutionPayloadAndBlobsBundle<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<BuilderBid<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBuilderBid<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
