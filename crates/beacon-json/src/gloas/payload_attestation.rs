//! Votes of the payload timeliness committee, from the Gloas beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    gloas::{PayloadAttestation, PayloadAttestationData, PayloadAttestationMessage},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for PayloadAttestationData {
    fn to_json(&self) -> Json {
        Json::from([
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("slot", self.slot.to_json()),
            ("payload_present", self.payload_present.to_json()),
            ("blob_data_available", self.blob_data_available.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            beacon_block_root: fields.required("beacon_block_root")?,
            slot: fields.required("slot")?,
            payload_present: fields.required("payload_present")?,
            blob_data_available: fields.required("blob_data_available")?,
        })
    }
}

impl<P: Preset> ApiJson for PayloadAttestation<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            aggregation_bits: fields.required("aggregation_bits")?,
            data: fields.required("data")?,
            signature: fields.required("signature")?,
        })
    }
}

impl ApiJson for PayloadAttestationMessage {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            data: fields.required("data")?,
            signature: fields.required("signature")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, Root, Slot};
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for PayloadAttestationData {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                beacon_block_root: sampler.draw(),
                slot: sampler.draw(),
                payload_present: sampler.draw(),
                blob_data_available: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for PayloadAttestation<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                aggregation_bits: sampler.draw(),
                data: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for PayloadAttestationMessage {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                validator_index: sampler.draw(),
                data: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    #[test]
    fn booleans_are_json_literals() {
        // Fixture state: slot 9, payload present, blobs not available.
        let data = PayloadAttestationData {
            beacon_block_root: Root([0; 32]),
            slot: Slot(9),
            payload_present: true,
            blob_data_available: false,
        };
        let root = format!("0x{}", "00".repeat(32));
        assert_eq!(
            data.to_json(),
            Json::from([
                ("beacon_block_root", Json::from(root.as_str())),
                ("slot", Json::from("9")),
                ("payload_present", Json::Bool(true)),
                ("blob_data_available", Json::Bool(false)),
            ])
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn payload_attestations_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<PayloadAttestationData>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<PayloadAttestation<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<PayloadAttestationMessage>().map_err(TestCaseError::fail)?;
        }
    }
}
