//! Sync committee messages and aggregates, from the Altair beacon chain and validator specs.

use axiom_json::Json;
use axiom_types::{
    Preset,
    altair::{
        ContributionAndProof, SignedContributionAndProof, SyncAggregate, SyncCommitteeContribution,
        SyncCommitteeMessage,
    },
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for SyncAggregate<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("sync_committee_bits", self.sync_committee_bits.to_json()),
            (
                "sync_committee_signature",
                self.sync_committee_signature.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            sync_committee_bits: fields.required("sync_committee_bits")?,
            sync_committee_signature: fields.required("sync_committee_signature")?,
        })
    }
}

impl ApiJson for SyncCommitteeMessage {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            slot: fields.required("slot")?,
            beacon_block_root: fields.required("beacon_block_root")?,
            validator_index: fields.required("validator_index")?,
            signature: fields.required("signature")?,
        })
    }
}

impl<P: Preset> ApiJson for SyncCommitteeContribution<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("subcommittee_index", self.subcommittee_index.to_json()),
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            slot: fields.required("slot")?,
            beacon_block_root: fields.required("beacon_block_root")?,
            subcommittee_index: fields.required("subcommittee_index")?,
            aggregation_bits: fields.required("aggregation_bits")?,
            signature: fields.required("signature")?,
        })
    }
}

impl<P: Preset> ApiJson for ContributionAndProof<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregator_index", self.aggregator_index.to_json()),
            ("contribution", self.contribution.to_json()),
            ("selection_proof", self.selection_proof.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            aggregator_index: fields.required("aggregator_index")?,
            contribution: fields.required("contribution")?,
            selection_proof: fields.required("selection_proof")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedContributionAndProof<P> {
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

    impl<P: Preset> Sample for SyncAggregate<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                sync_committee_bits: sampler.draw(),
                sync_committee_signature: sampler.draw(),
            }
        }
    }

    impl Sample for SyncCommitteeMessage {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                slot: sampler.draw(),
                beacon_block_root: sampler.draw(),
                validator_index: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SyncCommitteeContribution<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                slot: sampler.draw(),
                beacon_block_root: sampler.draw(),
                subcommittee_index: sampler.draw(),
                aggregation_bits: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for ContributionAndProof<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                aggregator_index: sampler.draw(),
                contribution: sampler.draw(),
                selection_proof: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for SignedContributionAndProof<P> {
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
        fn sync_committee_messages_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<SyncAggregate<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SyncCommitteeMessage>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SyncCommitteeContribution<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ContributionAndProof<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedContributionAndProof<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
