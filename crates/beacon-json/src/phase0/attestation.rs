//! Attestations and their aggregates, from the phase0 beacon chain and validator specs.

use axiom_json::Json;
use axiom_types::{
    Preset,
    phase0::{
        AggregateAndProof, Attestation, AttestationData, Checkpoint, IndexedAttestation,
        SignedAggregateAndProof,
    },
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for Checkpoint {
    fn to_json(&self) -> Json {
        Json::from([
            ("epoch", self.epoch.to_json()),
            ("root", self.root.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            epoch: fields.required("epoch")?,
            root: fields.required("root")?,
        })
    }
}

impl ApiJson for AttestationData {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("index", self.index.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("source", self.source.to_json()),
            ("target", self.target.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            slot: fields.required("slot")?,
            index: fields.required("index")?,
            beacon_block_root: fields.required("beacon_block_root")?,
            source: fields.required("source")?,
            target: fields.required("target")?,
        })
    }
}

impl<P: Preset> ApiJson for Attestation<P> {
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

impl<P: Preset> ApiJson for IndexedAttestation<P> {
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
    use axiom_types::{CommitteeIndex, Epoch, Minimal, Root, Slot};
    use proptest::prelude::*;

    use super::*;
    use crate::{
        ApiJsonErrorKind,
        sample::{Sample, Sampler},
    };

    impl Sample for Checkpoint {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                epoch: sampler.draw(),
                root: sampler.draw(),
            }
        }
    }

    impl Sample for AttestationData {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                slot: sampler.draw(),
                index: sampler.draw(),
                beacon_block_root: sampler.draw(),
                source: sampler.draw(),
                target: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for Attestation<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                aggregation_bits: sampler.draw(),
                data: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for IndexedAttestation<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                attesting_indices: sampler.draw(),
                data: sampler.draw(),
                signature: sampler.draw(),
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

    #[test]
    fn attestation_data_has_the_api_shape() {
        // Fixture state: slot 33, committee 2, source epoch 3, target epoch 4.
        // The block, source, and target roots are all ones, all twos, and all threes.
        let data = AttestationData {
            slot: Slot(33),
            index: CommitteeIndex(2),
            beacon_block_root: Root([1; 32]),
            source: Checkpoint {
                epoch: Epoch(3),
                root: Root([2; 32]),
            },
            target: Checkpoint {
                epoch: Epoch(4),
                root: Root([3; 32]),
            },
        };
        let ones = "01".repeat(32);
        let twos = "02".repeat(32);
        let threes = "03".repeat(32);

        // Integers are quoted decimals, roots are hex, and members follow the spec's order.
        let expected = [
            r#"{"slot":"33","index":"2","beacon_block_root":"0x"#,
            &ones,
            r#"","source":{"epoch":"3","root":"0x"#,
            &twos,
            r#""},"target":{"epoch":"4","root":"0x"#,
            &threes,
            r#""}}"#,
        ]
        .concat();
        assert_eq!(data.to_json().to_string(), expected);
        assert_eq!(
            AttestationData::from_json(&Json::parse(&expected).unwrap()),
            Ok(data)
        );
    }

    #[test]
    fn a_checkpoint_ignores_unknown_members_and_needs_known_ones() {
        // An extra member is ignored.
        let root = format!("0x{}", "00".repeat(32));
        let extra = Json::from([
            ("epoch", Json::from("7")),
            ("root", Json::from(root.as_str())),
            ("comment", Json::from("ignored")),
        ]);
        assert_eq!(
            Checkpoint::from_json(&extra),
            Ok(Checkpoint {
                epoch: Epoch(7),
                root: Root([0; 32]),
            })
        );

        // A missing root is named.
        let partial = Json::from([("epoch", Json::from("7"))]);
        assert_eq!(
            Checkpoint::from_json(&partial),
            Err(ApiJsonError::new(ApiJsonErrorKind::Missing).in_member("root"))
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn attestations_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<Checkpoint>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<AttestationData>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<Attestation<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<IndexedAttestation<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<AggregateAndProof<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedAggregateAndProof<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
