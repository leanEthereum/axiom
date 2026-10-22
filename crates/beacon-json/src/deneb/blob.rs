//! The blob sidecar, from the Deneb networking spec.

use axiom_json::Json;
use axiom_types::{Preset, deneb::BlobSidecar};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BlobSidecar<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("blob", self.blob.to_json()),
            ("kzg_commitment", self.kzg_commitment.to_json()),
            ("kzg_proof", self.kzg_proof.to_json()),
            ("signed_block_header", self.signed_block_header.to_json()),
            (
                "kzg_commitment_inclusion_proof",
                self.kzg_commitment_inclusion_proof.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            blob: fields.required("blob")?,
            kzg_commitment: fields.required("kzg_commitment")?,
            kzg_proof: fields.required("kzg_proof")?,
            signed_block_header: fields.required("signed_block_header")?,
            kzg_commitment_inclusion_proof: fields.required("kzg_commitment_inclusion_proof")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl<P: Preset> Sample for BlobSidecar<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                index: sampler.draw(),
                blob: sampler.draw(),
                kzg_commitment: sampler.draw(),
                kzg_proof: sampler.draw(),
                signed_block_header: sampler.draw(),
                kzg_commitment_inclusion_proof: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn blob_sidecars_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BlobSidecar<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
