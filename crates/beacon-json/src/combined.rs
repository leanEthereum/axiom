//! JSON forms of the containers of any fork, whose fork travels beside the value.
//!
//! The beacon API names the fork in a version header or member, never inside the container.
//! Encoding writes the variant's container as is.
//! Decoding reads the container of the fork the caller names.
//!
//! Unknown members are ignored, so a newer fork's JSON can read as an older fork's container.
//! The caller's fork, not the shape of the value, therefore decides the variant.

use axiom_json::Json;
use axiom_types::{
    ForkName, Preset,
    combined::{
        BeaconBlock, BeaconState, BlindedBeaconBlock, DataColumnSidecar, ExecutionPayload,
        SignedBeaconBlock, SignedBlindedBeaconBlock, SignedBuilderBid,
    },
};

use crate::{ApiJson, ApiJsonError, ForkedJson};

impl<P: Preset> ForkedJson for BeaconBlock<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Phase0(block) => block.to_json(),
            Self::Altair(block) => block.to_json(),
            Self::Bellatrix(block) => block.to_json(),
            Self::Capella(block) => block.to_json(),
            Self::Deneb(block) => block.to_json(),
            Self::Electra(block) | Self::Fulu(block) => block.to_json(),
            Self::Gloas(block) => block.to_json(),
            Self::Hstar(block) => block.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            ForkName::Phase0 => Self::Phase0(ApiJson::from_json(value)?),
            ForkName::Altair => Self::Altair(ApiJson::from_json(value)?),
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
            ForkName::Gloas => Self::Gloas(ApiJson::from_json(value)?),
            ForkName::Hstar => Self::Hstar(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for SignedBeaconBlock<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Phase0(block) => block.to_json(),
            Self::Altair(block) => block.to_json(),
            Self::Bellatrix(block) => block.to_json(),
            Self::Capella(block) => block.to_json(),
            Self::Deneb(block) => block.to_json(),
            Self::Electra(block) | Self::Fulu(block) => block.to_json(),
            Self::Gloas(block) => block.to_json(),
            Self::Hstar(block) => block.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            ForkName::Phase0 => Self::Phase0(ApiJson::from_json(value)?),
            ForkName::Altair => Self::Altair(ApiJson::from_json(value)?),
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
            ForkName::Gloas => Self::Gloas(ApiJson::from_json(value)?),
            ForkName::Hstar => Self::Hstar(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for BeaconState<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Phase0(state) => state.to_json(),
            Self::Altair(state) => state.to_json(),
            Self::Bellatrix(state) => state.to_json(),
            Self::Capella(state) => state.to_json(),
            Self::Deneb(state) => state.to_json(),
            Self::Electra(state) => state.to_json(),
            Self::Fulu(state) => state.to_json(),
            Self::Gloas(state) => state.to_json(),
            Self::Hstar(state) => state.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            ForkName::Phase0 => Self::Phase0(ApiJson::from_json(value)?),
            ForkName::Altair => Self::Altair(ApiJson::from_json(value)?),
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
            ForkName::Gloas => Self::Gloas(ApiJson::from_json(value)?),
            ForkName::Hstar => Self::Hstar(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for BlindedBeaconBlock<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Bellatrix(block) => block.to_json(),
            Self::Capella(block) => block.to_json(),
            Self::Deneb(block) => block.to_json(),
            Self::Electra(block) | Self::Fulu(block) => block.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            // Blinding starts with the payload at Bellatrix and ends with the bid at Gloas.
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas | ForkName::Hstar => {
                return Err(ApiJsonError::absent(fork, "blinded block"));
            }
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for SignedBlindedBeaconBlock<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Bellatrix(block) => block.to_json(),
            Self::Capella(block) => block.to_json(),
            Self::Deneb(block) => block.to_json(),
            Self::Electra(block) | Self::Fulu(block) => block.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas | ForkName::Hstar => {
                return Err(ApiJsonError::absent(fork, "signed blinded block"));
            }
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for SignedBuilderBid<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Bellatrix(bid) => bid.to_json(),
            Self::Capella(bid) => bid.to_json(),
            Self::Deneb(bid) => bid.to_json(),
            Self::Electra(bid) | Self::Fulu(bid) => bid.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            // The builder API sells payloads from Bellatrix until Gloas enshrines the bid.
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas | ForkName::Hstar => {
                return Err(ApiJsonError::absent(fork, "signed builder bid"));
            }
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for ExecutionPayload<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Bellatrix(payload) => payload.to_json(),
            Self::Capella(payload) => payload.to_json(),
            Self::Deneb(payload) | Self::Electra(payload) | Self::Fulu(payload) => {
                payload.to_json()
            }
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            // Gloas moves the payload into an envelope, a container of its own.
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas | ForkName::Hstar => {
                return Err(ApiJsonError::absent(fork, "execution payload in its block"));
            }
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> ForkedJson for DataColumnSidecar<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Fulu(sidecar) => sidecar.to_json(),
            Self::Gloas(sidecar) => sidecar.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            // Data columns start with peer sampling at Fulu.
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra => return Err(ApiJsonError::absent(fork, "data column sidecar")),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
            ForkName::Gloas | ForkName::Hstar => Self::Gloas(ApiJson::from_json(value)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Minimal, Slot, altair, bellatrix, capella, deneb, electra, fulu, gloas, phase0,
    };

    use super::*;
    use crate::{ApiJsonErrorKind, DecimalError};

    /// One empty block per fork, each at its own slot so no two encode alike.
    fn blocks() -> Vec<(ForkName, BeaconBlock<Minimal>)> {
        vec![
            (
                ForkName::Phase0,
                BeaconBlock::Phase0(phase0::BeaconBlock {
                    slot: Slot(1),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Altair,
                BeaconBlock::Altair(altair::BeaconBlock {
                    slot: Slot(2),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Bellatrix,
                BeaconBlock::Bellatrix(bellatrix::BeaconBlock {
                    slot: Slot(3),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Capella,
                BeaconBlock::Capella(capella::BeaconBlock {
                    slot: Slot(4),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Deneb,
                BeaconBlock::Deneb(deneb::BeaconBlock {
                    slot: Slot(5),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Electra,
                BeaconBlock::Electra(electra::BeaconBlock {
                    slot: Slot(6),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Fulu,
                BeaconBlock::Fulu(fulu::BeaconBlock {
                    slot: Slot(7),
                    ..Default::default()
                }),
            ),
            (
                ForkName::Gloas,
                BeaconBlock::Gloas(gloas::BeaconBlock {
                    slot: Slot(8),
                    ..Default::default()
                }),
            ),
        ]
    }

    #[test]
    fn every_fork_reads_back_as_itself() {
        // Each of the eight blocks returns as the variant of the fork it is read in.
        for (fork, block) in blocks() {
            let json = block.to_json();
            assert_eq!(
                BeaconBlock::<Minimal>::from_json_in(fork, &json),
                Ok(block),
                "{fork}"
            );
        }
    }

    #[test]
    fn the_caller_fork_decides_between_identical_shapes() {
        // Fixture state: an Electra block, whose shape Fulu keeps unchanged.
        // Read in Fulu, it becomes the Fulu variant of the same block.
        let block = electra::BeaconBlock::<Minimal> {
            slot: Slot(9),
            ..Default::default()
        };
        let json = BeaconBlock::Electra(block.clone()).to_json();
        assert_eq!(
            BeaconBlock::<Minimal>::from_json_in(ForkName::Fulu, &json),
            Ok(BeaconBlock::Fulu(block))
        );
    }

    #[test]
    fn an_older_fork_misses_members_of_a_newer_block() {
        // Fixture state: a Capella block read as Deneb.
        // Members decode in field order, and the payload precedes the blob commitments.
        // So the first member Deneb needs and Capella lacks is the payload's blob gas used.
        let json = BeaconBlock::Capella(capella::BeaconBlock::<Minimal>::default()).to_json();
        assert_eq!(
            BeaconBlock::<Minimal>::from_json_in(ForkName::Deneb, &json),
            Err(ApiJsonError::new(ApiJsonErrorKind::Missing)
                .in_member("blob_gas_used")
                .in_member("execution_payload")
                .in_member("body"))
        );
    }

    #[test]
    fn forks_without_the_container_are_refused() {
        // Phase0 has no blinded block, Gloas no builder bid, and Deneb no data column.
        let anything = Json::Null;
        assert_eq!(
            BlindedBeaconBlock::<Minimal>::from_json_in(ForkName::Phase0, &anything),
            Err(ApiJsonError::absent(ForkName::Phase0, "blinded block"))
        );
        assert_eq!(
            SignedBuilderBid::<Minimal>::from_json_in(ForkName::Gloas, &anything),
            Err(ApiJsonError::absent(ForkName::Gloas, "signed builder bid"))
        );
        assert_eq!(
            DataColumnSidecar::<Minimal>::from_json_in(ForkName::Deneb, &anything),
            Err(ApiJsonError::absent(ForkName::Deneb, "data column sidecar"))
        );
        assert_eq!(
            ApiJsonError::absent(ForkName::Gloas, "execution payload in its block").to_string(),
            "the gloas fork has no execution payload in its block"
        );
    }

    #[test]
    fn errors_name_the_path_through_the_block() {
        // Fixture state: a signed Deneb block at slot 5 with one attestation for slot 7.
        let mut signed = deneb::SignedBeaconBlock::<Minimal>::default();
        signed.message.slot = Slot(5);
        let mut attestation = phase0::Attestation::default();
        attestation.data.slot = Slot(7);
        signed.message.body.attestations.push(attestation).unwrap();
        let text = SignedBeaconBlock::Deneb(signed).to_json().to_string();

        // Mutation: the attestation's slot is written "07", a non-canonical decimal.
        let mutated = text.replace(r#""slot":"7""#, r#""slot":"07""#);
        assert_ne!(mutated, text);
        let json = Json::parse(mutated).unwrap();

        // The error walks message, body, the first attestation, its data, and its slot.
        let error = SignedBeaconBlock::<Minimal>::from_json_in(ForkName::Deneb, &json).unwrap_err();
        assert_eq!(
            error,
            ApiJsonError::new(ApiJsonErrorKind::Decimal(DecimalError::LeadingZero))
                .in_member("slot")
                .in_member("data")
                .at_index(0)
                .in_member("attestations")
                .in_member("body")
                .in_member("message")
        );
        assert_eq!(
            error.to_string(),
            "message.body.attestations[0].data.slot: decimal string has a leading zero"
        );
    }
}
