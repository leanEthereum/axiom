//! The data column sidecar, from the Fulu data availability spec.

use axiom_json::Json;
use axiom_types::{Preset, fulu::DataColumnSidecar};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for DataColumnSidecar<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("column", self.column.to_json()),
            ("kzg_commitments", self.kzg_commitments.to_json()),
            ("kzg_proofs", self.kzg_proofs.to_json()),
            ("signed_block_header", self.signed_block_header.to_json()),
            (
                "kzg_commitments_inclusion_proof",
                self.kzg_commitments_inclusion_proof.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            column: fields.required("column")?,
            kzg_commitments: fields.required("kzg_commitments")?,
            kzg_proofs: fields.required("kzg_proofs")?,
            signed_block_header: fields.required("signed_block_header")?,
            kzg_commitments_inclusion_proof: fields.required("kzg_commitments_inclusion_proof")?,
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
                kzg_commitments: sampler.draw(),
                kzg_proofs: sampler.draw(),
                signed_block_header: sampler.draw(),
                kzg_commitments_inclusion_proof: sampler.draw(),
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
