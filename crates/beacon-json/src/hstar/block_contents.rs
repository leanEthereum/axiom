//! An Hstar block with its payload envelope, blobs, and cell proofs, as the beacon API produces it.

use axiom_json::Json;
use axiom_types::{Preset, hstar::BlockContents};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BlockContents<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("block", self.block.to_json()),
            (
                "execution_payload_envelope",
                self.execution_payload_envelope.to_json(),
            ),
            ("kzg_proofs", self.kzg_proofs.to_json()),
            ("blobs", self.blobs.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            block: fields.required("block")?,
            execution_payload_envelope: fields.required("execution_payload_envelope")?,
            kzg_proofs: fields.required("kzg_proofs")?,
            blobs: fields.required("blobs")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl<P: Preset> Sample for BlockContents<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                block: sampler.draw(),
                execution_payload_envelope: sampler.draw(),
                kzg_proofs: sampler.draw(),
                blobs: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn block_contents_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BlockContents<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
