//! An Electra block with its blobs and proofs, as the beacon API produces and publishes it.

use axiom_json::Json;
use axiom_types::{
    Preset,
    electra::{BlockContents, SignedBlockContents},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BlockContents<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("block", self.block.to_json()),
            ("kzg_proofs", self.kzg_proofs.to_json()),
            ("blobs", self.blobs.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            block: fields.required("block")?,
            kzg_proofs: fields.required("kzg_proofs")?,
            blobs: fields.required("blobs")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedBlockContents<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("signed_block", self.signed_block.to_json()),
            ("kzg_proofs", self.kzg_proofs.to_json()),
            ("blobs", self.blobs.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            signed_block: fields.required("signed_block")?,
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
                kzg_proofs: sampler.draw(),
                blobs: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SignedBlockContents<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                signed_block: sampler.draw(),
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
            sampler.round_trip::<SignedBlockContents<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
