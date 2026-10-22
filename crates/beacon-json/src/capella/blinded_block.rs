//! The Capella blinded block, from the Capella builder spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    capella::{BlindedBeaconBlock, BlindedBeaconBlockBody, SignedBlindedBeaconBlock},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BlindedBeaconBlockBody<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("randao_reveal", self.randao_reveal.to_json()),
            ("eth1_data", self.eth1_data.to_json()),
            ("graffiti", self.graffiti.to_json()),
            ("proposer_slashings", self.proposer_slashings.to_json()),
            ("attester_slashings", self.attester_slashings.to_json()),
            ("attestations", self.attestations.to_json()),
            ("deposits", self.deposits.to_json()),
            ("voluntary_exits", self.voluntary_exits.to_json()),
            ("sync_aggregate", self.sync_aggregate.to_json()),
            (
                "execution_payload_header",
                self.execution_payload_header.to_json(),
            ),
            (
                "bls_to_execution_changes",
                self.bls_to_execution_changes.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            randao_reveal: fields.required("randao_reveal")?,
            eth1_data: fields.required("eth1_data")?,
            graffiti: fields.required("graffiti")?,
            proposer_slashings: fields.required("proposer_slashings")?,
            attester_slashings: fields.required("attester_slashings")?,
            attestations: fields.required("attestations")?,
            deposits: fields.required("deposits")?,
            voluntary_exits: fields.required("voluntary_exits")?,
            sync_aggregate: fields.required("sync_aggregate")?,
            execution_payload_header: fields.required("execution_payload_header")?,
            bls_to_execution_changes: fields.required("bls_to_execution_changes")?,
        })
    }
}

impl<P: Preset> ApiJson for BlindedBeaconBlock<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("proposer_index", self.proposer_index.to_json()),
            ("parent_root", self.parent_root.to_json()),
            ("state_root", self.state_root.to_json()),
            ("body", self.body.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            slot: fields.required("slot")?,
            proposer_index: fields.required("proposer_index")?,
            parent_root: fields.required("parent_root")?,
            state_root: fields.required("state_root")?,
            body: fields.required("body")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedBlindedBeaconBlock<P> {
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

    impl<P: Preset> Sample for BlindedBeaconBlockBody<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                randao_reveal: sampler.draw(),
                eth1_data: sampler.draw(),
                graffiti: sampler.draw(),
                proposer_slashings: sampler.draw(),
                attester_slashings: sampler.draw(),
                attestations: sampler.draw(),
                deposits: sampler.draw(),
                voluntary_exits: sampler.draw(),
                sync_aggregate: sampler.draw(),
                execution_payload_header: sampler.draw(),
                bls_to_execution_changes: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for BlindedBeaconBlock<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                slot: sampler.draw(),
                proposer_index: sampler.draw(),
                parent_root: sampler.draw(),
                state_root: sampler.draw(),
                body: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SignedBlindedBeaconBlock<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn blinded_blocks_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BlindedBeaconBlockBody<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<BlindedBeaconBlock<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBlindedBeaconBlock<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
