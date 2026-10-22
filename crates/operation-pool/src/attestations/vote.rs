//! A vote of one committee, in the form the pool keeps whatever the fork.

use axiom_types::{
    CommitteeIndex, Preset, ValidatorIndex,
    electra::{self, SingleAttestation},
    gloas,
    phase0::{self, AttestationData},
    vote::CommitteeVote,
};

use crate::{Aggregate, Bits, PoolError};

/// Signers of one committee over one attestation data, with their aggregate signature.
///
/// Phase0 names the committee in the data; Electra names it beside the data.
/// Either way, the pool keeps the committee and the data apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeAggregate {
    /// The vote.
    pub data: AttestationData,
    /// The committee that signed it.
    pub committee: CommitteeIndex,
    /// The signers, at their positions in the committee.
    pub aggregate: Aggregate,
}

impl CommitteeAggregate {
    /// A phase0 attestation, whose data names its committee.
    ///
    /// Phase0 attestations travel unchanged until Electra.
    #[must_use]
    pub fn phase0<P: Preset>(attestation: &phase0::Attestation<P>) -> Self {
        Self {
            data: attestation.data.clone(),
            committee: attestation.data.index,
            aggregate: Aggregate {
                bits: Bits::from_bools(attestation.aggregation_bits.iter()),
                signature: attestation.signature,
            },
        }
    }

    /// An Electra attestation of exactly one committee, as aggregators publish.
    ///
    /// # Errors
    ///
    /// Fails when the committee bits name no committee or several.
    pub fn electra<P: Preset>(attestation: &electra::Attestation<P>) -> Result<Self, PoolError> {
        let committee = Self::sole_committee(attestation.committee_indices())?;
        Ok(Self {
            data: attestation.data.clone(),
            committee,
            aggregate: Aggregate {
                bits: Bits::from_bools(attestation.aggregation_bits.iter()),
                signature: attestation.signature,
            },
        })
    }

    /// A Gloas attestation of exactly one committee.
    ///
    /// # Errors
    ///
    /// Fails when the committee bits name no committee or several.
    pub fn gloas<P: Preset>(attestation: &gloas::Attestation<P>) -> Result<Self, PoolError> {
        let committee = Self::sole_committee(attestation.committee_indices())?;
        Ok(Self {
            data: attestation.data.clone(),
            committee,
            aggregate: Aggregate {
                bits: Bits::from_bools(attestation.aggregation_bits.iter()),
                signature: attestation.signature,
            },
        })
    }

    /// A vote of exactly one committee, in the form every fork shares.
    ///
    /// Gossip hands aggregates and single votes over in that form once they pass its rules.
    ///
    /// # Errors
    ///
    /// Fails when the vote names no committee or several.
    pub fn from_vote(vote: &CommitteeVote) -> Result<Self, PoolError> {
        let committee = Self::sole_committee(vote.committees.iter().copied())?;
        Ok(Self {
            data: vote.data.clone(),
            committee,
            aggregate: Aggregate {
                bits: Bits::from_bools(vote.bits.iter().copied()),
                signature: vote.signature,
            },
        })
    }

    /// One validator's vote, at its place in the committee it names.
    ///
    /// # Errors
    ///
    /// Fails when the attester is not a member of the committee.
    pub fn single(
        attestation: &SingleAttestation,
        committee: &[ValidatorIndex],
    ) -> Result<Self, PoolError> {
        let position = committee
            .iter()
            .position(|member| *member == attestation.attester_index)
            .ok_or(PoolError::NotInCommittee {
                validator: attestation.attester_index,
                committee: attestation.committee_index,
            })?;
        Ok(Self {
            data: attestation.data.clone(),
            committee: attestation.committee_index,
            aggregate: Aggregate {
                bits: Bits::single(committee.len(), position),
                signature: attestation.signature,
            },
        })
    }

    /// The one committee a set of committee bits names.
    fn sole_committee(
        mut indices: impl Iterator<Item = CommitteeIndex>,
    ) -> Result<CommitteeIndex, PoolError> {
        match (indices.next(), indices.next()) {
            (Some(committee), None) => Ok(committee),
            (None, _) => Err(PoolError::CommitteeCount(0)),
            (Some(_), Some(_)) => Err(PoolError::CommitteeCount(2 + indices.count())),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, Slot, electra::CommitteeBits};

    use super::*;

    #[test]
    fn an_electra_aggregate_names_exactly_one_committee() {
        // Fixture state: an aggregate of committee 2 at slot 9, two of three members signing.
        let mut attestation = electra::Attestation::<Minimal> {
            data: AttestationData {
                slot: Slot(9),
                ..AttestationData::default()
            },
            committee_bits: CommitteeBits::<Minimal>::new(),
            ..electra::Attestation::default()
        };
        attestation.committee_bits.set(2, true);
        attestation.aggregation_bits = Bits::from_bools([true, false, true].into_iter())
            .to_bit_list()
            .unwrap();

        let vote = CommitteeAggregate::electra(&attestation).unwrap();
        assert_eq!(vote.committee, CommitteeIndex(2));
        assert_eq!(vote.aggregate.bits.ones().collect::<Vec<_>>(), [0, 2]);

        // Mutation: committee 3 is named too, which no aggregator publishes.
        attestation.committee_bits.set(3, true);
        assert_eq!(
            CommitteeAggregate::electra(&attestation),
            Err(PoolError::CommitteeCount(2))
        );
        // Mutation: no committee at all.
        attestation.committee_bits = CommitteeBits::<Minimal>::new();
        assert_eq!(
            CommitteeAggregate::electra(&attestation),
            Err(PoolError::CommitteeCount(0))
        );
    }

    #[test]
    fn a_single_vote_sits_at_its_attester_place() {
        // Fixture state: committee 1 is validators 7, 4, 9; validator 9 votes.
        let attestation = SingleAttestation {
            committee_index: CommitteeIndex(1),
            attester_index: ValidatorIndex(9),
            ..SingleAttestation::default()
        };
        let committee = [7, 4, 9].map(ValidatorIndex);

        let vote = CommitteeAggregate::single(&attestation, &committee).unwrap();
        assert_eq!(vote.aggregate.bits, Bits::single(3, 2));

        // Validator 5 sits in no seat of the committee.
        let stranger = SingleAttestation {
            attester_index: ValidatorIndex(5),
            ..attestation
        };
        assert_eq!(
            CommitteeAggregate::single(&stranger, &committee),
            Err(PoolError::NotInCommittee {
                validator: ValidatorIndex(5),
                committee: CommitteeIndex(1),
            })
        );
    }
}
