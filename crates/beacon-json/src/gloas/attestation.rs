//! Attestations over progressive lists, see EIP-7688 and the Gloas beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    gloas::{
        AggregateAndProof, Attestation, AttesterSlashing, IndexedAttestation,
        SignedAggregateAndProof,
    },
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for Attestation<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
            ("committee_bits", self.committee_bits.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            aggregation_bits: fields.required("aggregation_bits")?,
            data: fields.required("data")?,
            signature: fields.required("signature")?,
            committee_bits: fields.required("committee_bits")?,
        })
    }
}

impl ApiJson for IndexedAttestation {
    fn to_json(&self) -> Json {
        Json::from([
            ("attesting_indices", self.attesting_indices.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            attesting_indices: fields.required("attesting_indices")?,
            data: fields.required("data")?,
            signature: fields.required("signature")?,
        })
    }
}

impl ApiJson for AttesterSlashing {
    fn to_json(&self) -> Json {
        Json::from([
            ("attestation_1", self.attestation_1.to_json()),
            ("attestation_2", self.attestation_2.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            attestation_1: fields.required("attestation_1")?,
            attestation_2: fields.required("attestation_2")?,
        })
    }
}

impl<P: Preset> ApiJson for AggregateAndProof<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregator_index", self.aggregator_index.to_json()),
            ("aggregate", self.aggregate.to_json()),
            ("selection_proof", self.selection_proof.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            aggregator_index: fields.required("aggregator_index")?,
            aggregate: fields.required("aggregate")?,
            selection_proof: fields.required("selection_proof")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedAggregateAndProof<P> {
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

    impl<P: Preset> Sample for Attestation<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                aggregation_bits: sampler.draw(),
                data: sampler.draw(),
                signature: sampler.draw(),
                committee_bits: sampler.draw(),
            }
        }
    }

    impl Sample for IndexedAttestation {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                attesting_indices: sampler.draw(),
                data: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for AttesterSlashing {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                attestation_1: sampler.draw(),
                attestation_2: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for AggregateAndProof<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                aggregator_index: sampler.draw(),
                aggregate: sampler.draw(),
                selection_proof: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SignedAggregateAndProof<P> {
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
        fn attestations_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<Attestation<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<IndexedAttestation>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<AttesterSlashing>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<AggregateAndProof<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedAggregateAndProof<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
