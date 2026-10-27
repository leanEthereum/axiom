//! Attestations and aggregates in the shape of the fork that carries them.

use axiom_beacon_json::{ApiJson, ApiJsonError, ForkedJson, api::AttesterDuty};
use axiom_json::Json;
use axiom_ssz::BitList;
use axiom_types::{
    BlsSignature, ForkName, Preset, ValidatorIndex, electra, gloas,
    phase0::{self, AttestationData},
};

use crate::{beacon::BeaconError, signing::AggregateAndProofRef};

/// One validator's vote, in the shape the pool route of its fork takes.
///
/// Before Electra a vote is an attestation with one bit set in its committee.
/// From Electra on it names its committee and attester directly.
/// See `submitPoolAttestationsV2` in the beacon API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolAttestation<P: Preset> {
    /// The phase0 to Deneb shape.
    Phase0(phase0::Attestation<P>),
    /// The Electra shape onwards.
    Single(electra::SingleAttestation),
}

impl<P: Preset> PoolAttestation<P> {
    /// A signed vote from a committee seat, in the shape of a fork.
    ///
    /// # Errors
    ///
    /// Fails when the duty's committee is too large or the seat lies outside it.
    pub fn new(
        fork: ForkName,
        duty: &AttesterDuty,
        data: AttestationData,
        signature: BlsSignature,
    ) -> Result<Self, BeaconError> {
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => {
                // One bit, at the attester's seat, in a list as long as the committee.
                let length = duty.committee_length as usize;
                let seat = duty.validator_committee_index as usize;
                let mut aggregation_bits =
                    BitList::with_len(length).map_err(|_| BeaconError::CommitteeTooLarge {
                        length: duty.committee_length,
                        max: P::MAX_VALIDATORS_PER_COMMITTEE,
                    })?;
                if seat >= length {
                    return Err(BeaconError::Seat {
                        seat: duty.validator_committee_index,
                        length: duty.committee_length,
                    });
                }
                aggregation_bits.set(seat, true);
                Ok(Self::Phase0(phase0::Attestation {
                    aggregation_bits,
                    data,
                    signature,
                }))
            }
            ForkName::Electra | ForkName::Fulu | ForkName::Gloas | ForkName::Hstar => {
                Ok(Self::Single(electra::SingleAttestation {
                    committee_index: duty.committee_index,
                    attester_index: duty.validator_index,
                    data,
                    signature,
                }))
            }
        }
    }

    /// The vote's data.
    #[must_use]
    pub const fn data(&self) -> &AttestationData {
        match self {
            Self::Phase0(attestation) => &attestation.data,
            Self::Single(attestation) => &attestation.data,
        }
    }
}

impl<P: Preset> ForkedJson for PoolAttestation<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Phase0(attestation) => attestation.to_json(),
            Self::Single(attestation) => attestation.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, json: &Json) -> Result<Self, ApiJsonError> {
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => phase0::Attestation::from_json(json).map(Self::Phase0),
            ForkName::Electra | ForkName::Fulu | ForkName::Gloas | ForkName::Hstar => {
                electra::SingleAttestation::from_json(json).map(Self::Single)
            }
        }
    }
}

/// A committee's aggregate vote, in the shape of its fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Aggregate<P: Preset> {
    /// The phase0 to Deneb shape.
    Phase0(phase0::Attestation<P>),
    /// The Electra and Fulu shape.
    Electra(electra::Attestation<P>),
    /// The Gloas shape.
    Gloas(gloas::Attestation<P>),
}

impl<P: Preset> Aggregate<P> {
    /// The vote the aggregate carries.
    #[must_use]
    pub const fn data(&self) -> &AttestationData {
        match self {
            Self::Phase0(aggregate) => &aggregate.data,
            Self::Electra(aggregate) => &aggregate.data,
            Self::Gloas(aggregate) => &aggregate.data,
        }
    }

    /// The aggregate with its aggregator's proof, ready to sign.
    #[must_use]
    pub fn with_proof(
        self,
        aggregator_index: ValidatorIndex,
        selection_proof: BlsSignature,
    ) -> AggregateAndProof<P> {
        match self {
            Self::Phase0(aggregate) => AggregateAndProof::Phase0(phase0::AggregateAndProof {
                aggregator_index,
                aggregate,
                selection_proof,
            }),
            Self::Electra(aggregate) => AggregateAndProof::Electra(electra::AggregateAndProof {
                aggregator_index,
                aggregate,
                selection_proof,
            }),
            Self::Gloas(aggregate) => AggregateAndProof::Gloas(gloas::AggregateAndProof {
                aggregator_index,
                aggregate,
                selection_proof,
            }),
        }
    }
}

impl<P: Preset> ForkedJson for Aggregate<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Phase0(aggregate) => aggregate.to_json(),
            Self::Electra(aggregate) => aggregate.to_json(),
            Self::Gloas(aggregate) => aggregate.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, json: &Json) -> Result<Self, ApiJsonError> {
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => phase0::Attestation::from_json(json).map(Self::Phase0),
            ForkName::Electra | ForkName::Fulu => {
                electra::Attestation::from_json(json).map(Self::Electra)
            }
            ForkName::Gloas | ForkName::Hstar => {
                gloas::Attestation::from_json(json).map(Self::Gloas)
            }
        }
    }
}

/// An aggregate with its aggregator's proof, in the shape of its fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AggregateAndProof<P: Preset> {
    /// The phase0 to Deneb shape.
    Phase0(phase0::AggregateAndProof<P>),
    /// The Electra and Fulu shape.
    Electra(electra::AggregateAndProof<P>),
    /// The Gloas shape.
    Gloas(gloas::AggregateAndProof<P>),
}

impl<P: Preset> AggregateAndProof<P> {
    /// The message as a signing request sees it.
    #[must_use]
    pub const fn as_ref(&self) -> AggregateAndProofRef<'_, P> {
        match self {
            Self::Phase0(message) => AggregateAndProofRef::Phase0(message),
            Self::Electra(message) => AggregateAndProofRef::Electra(message),
            Self::Gloas(message) => AggregateAndProofRef::Gloas(message),
        }
    }

    /// The signed message.
    #[must_use]
    pub fn sign(self, signature: BlsSignature) -> SignedAggregate<P> {
        match self {
            Self::Phase0(message) => {
                SignedAggregate::Phase0(phase0::SignedAggregateAndProof { message, signature })
            }
            Self::Electra(message) => {
                SignedAggregate::Electra(electra::SignedAggregateAndProof { message, signature })
            }
            Self::Gloas(message) => {
                SignedAggregate::Gloas(gloas::SignedAggregateAndProof { message, signature })
            }
        }
    }
}

/// A signed aggregate and proof, in the shape of its fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedAggregate<P: Preset> {
    /// The phase0 to Deneb shape.
    Phase0(phase0::SignedAggregateAndProof<P>),
    /// The Electra and Fulu shape.
    Electra(electra::SignedAggregateAndProof<P>),
    /// The Gloas shape.
    Gloas(gloas::SignedAggregateAndProof<P>),
}

impl<P: Preset> ForkedJson for SignedAggregate<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Phase0(signed) => signed.to_json(),
            Self::Electra(signed) => signed.to_json(),
            Self::Gloas(signed) => signed.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, json: &Json) -> Result<Self, ApiJsonError> {
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => phase0::SignedAggregateAndProof::from_json(json).map(Self::Phase0),
            ForkName::Electra | ForkName::Fulu => {
                electra::SignedAggregateAndProof::from_json(json).map(Self::Electra)
            }
            ForkName::Gloas | ForkName::Hstar => {
                gloas::SignedAggregateAndProof::from_json(json).map(Self::Gloas)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsPubkey, CommitteeIndex, Minimal, Slot};

    use super::*;

    /// Seat 2 of a 4-member committee 1, for validator 9 at slot 3.
    fn duty() -> AttesterDuty {
        AttesterDuty {
            pubkey: BlsPubkey::ZERO,
            validator_index: ValidatorIndex(9),
            committee_index: CommitteeIndex(1),
            committee_length: 4,
            committees_at_slot: 2,
            validator_committee_index: 2,
            slot: Slot(3),
        }
    }

    #[test]
    fn each_fork_votes_in_its_own_shape() {
        let data = AttestationData::default();

        // Deneb: one bit at seat 2 of 4, no attester index.
        let PoolAttestation::Phase0(vote) = PoolAttestation::<Minimal>::new(
            ForkName::Deneb,
            &duty(),
            data.clone(),
            BlsSignature([1; 96]),
        )
        .unwrap() else {
            panic!("a Deneb vote is a phase0 attestation");
        };
        let bits: Vec<bool> = vote.aggregation_bits.iter().collect();
        assert_eq!(bits, [false, false, true, false]);

        // Electra: the committee and attester by index.
        assert_eq!(
            PoolAttestation::<Minimal>::new(
                ForkName::Electra,
                &duty(),
                data.clone(),
                BlsSignature([1; 96])
            )
            .unwrap(),
            PoolAttestation::Single(electra::SingleAttestation {
                committee_index: CommitteeIndex(1),
                attester_index: ValidatorIndex(9),
                data,
                signature: BlsSignature([1; 96]),
            })
        );
    }

    #[test]
    fn a_seat_outside_the_committee_is_refused() {
        // Mutation: seat 4 of a committee of 4.
        let mut duty = duty();
        duty.validator_committee_index = 4;
        assert!(matches!(
            PoolAttestation::<Minimal>::new(
                ForkName::Phase0,
                &duty,
                AttestationData::default(),
                BlsSignature::default()
            ),
            Err(BeaconError::Seat { seat: 4, length: 4 })
        ));
    }
}
