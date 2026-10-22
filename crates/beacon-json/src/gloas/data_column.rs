//! The Gloas data column sidecar, which names its block instead of proving inclusion.

use axiom_json::Json;
use axiom_types::{Preset, gloas::DataColumnSidecar};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for DataColumnSidecar<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("column", self.column.to_json()),
            ("kzg_proofs", self.kzg_proofs.to_json()),
            ("slot", self.slot.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            column: fields.required("column")?,
            kzg_proofs: fields.required("kzg_proofs")?,
            slot: fields.required("slot")?,
            beacon_block_root: fields.required("beacon_block_root")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl<P: Preset> Sample for DataColumnSidecar<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                index: sampler.draw(),
                column: sampler.draw(),
                kzg_proofs: sampler.draw(),
                slot: sampler.draw(),
                beacon_block_root: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn data_columns_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<DataColumnSidecar<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
