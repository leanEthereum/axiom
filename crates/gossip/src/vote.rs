//! Votes and slashing evidence as gossip rules read them, whatever their fork's container.
//!
//! # Overview
//!
//! Phase0, Electra, and Gloas each define their own attestation containers.
//! The rules that check them read the same few fields.
//! Each trait here names those fields, and each fork's container implements it.

use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, CommitteeIndex, ValidatorIndex,
    phase0::AttestationData,
    vote::{CommitteeVote, ConflictingVotes},
};

use crate::{Detail, GossipError};

/// An aggregate of votes from one committee, as the aggregate topic carries it.
pub trait Aggregate {
    /// The vote.
    fn data(&self) -> &AttestationData;

    /// Which committee members signed, in committee order.
    fn bits(&self) -> Vec<bool>;

    /// Aggregate signature of every participant.
    fn signature(&self) -> &BlsSignature;

    /// The one committee the aggregate covers.
    ///
    /// # Errors
    ///
    /// Rejects an aggregate that names no committee or several.
    fn committee(&self) -> Result<CommitteeIndex, GossipError>;

    /// The aggregate as the fork choice counts it.
    fn committee_vote(&self) -> CommitteeVote;
}

/// An aggregate with its aggregator's selection proof and signature.
pub trait SignedAggregate {
    /// The signed message: the aggregate, the aggregator, and the selection proof.
    type Message: Ssz;

    /// The aggregate attestation.
    type Aggregate: Aggregate;

    /// The signed message.
    fn message(&self) -> &Self::Message;

    /// The aggregate attestation.
    fn aggregate(&self) -> &Self::Aggregate;

    /// The aggregator.
    fn aggregator_index(&self) -> ValidatorIndex;

    /// Signature over the slot, whose hash proves selection.
    fn selection_proof(&self) -> &BlsSignature;

    /// Aggregator's signature over the message.
    fn signature(&self) -> &BlsSignature;
}

/// One validator's vote, as an attestation subnet carries it.
pub trait SubnetVote {
    /// The vote.
    fn data(&self) -> &AttestationData;

    /// The voter's signature.
    fn signature(&self) -> &BlsSignature;

    /// The committee the voter sits in.
    fn committee_index(&self) -> CommitteeIndex;

    /// The voter, found in its committee.
    ///
    /// # Errors
    ///
    /// Rejects a vote whose voter the committee does not hold.
    fn attester(&self, committee: &[ValidatorIndex]) -> Result<ValidatorIndex, GossipError>;
}

impl SubnetVote for CommitteeVote {
    fn data(&self) -> &AttestationData {
        &self.data
    }

    fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    fn committee_index(&self) -> CommitteeIndex {
        // A vote with one signer names one committee; an empty list names none, read as zero.
        self.committees.first().copied().unwrap_or_default()
    }

    fn attester(&self, committee: &[ValidatorIndex]) -> Result<ValidatorIndex, GossipError> {
        let signers: Vec<usize> = self
            .bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .map(|(position, _)| position)
            .collect();
        if self.committees.len() != 1 || signers.len() != 1 {
            return Err(GossipError::reject("vote is not from one validator").with(
                Detail::Mismatch {
                    actual: signers.len() as u64,
                    expected: 1,
                },
            ));
        }
        if self.bits.len() != committee.len() {
            return Err(GossipError::reject(
                "aggregation bits length does not match committee size",
            )
            .with(Detail::Mismatch {
                actual: self.bits.len() as u64,
                expected: committee.len() as u64,
            }));
        }
        // Invariant: one signer, at a position the committee's length bounds.
        Ok(committee[signers[0]])
    }
}

/// A vote with its signers listed by validator index.
#[derive(Clone, Copy, Debug)]
pub struct IndexedVote<'a> {
    /// The signers, which must be sorted and unique.
    pub indices: &'a [ValidatorIndex],
    /// The vote.
    pub data: &'a AttestationData,
    /// Aggregate signature of the signers.
    pub signature: &'a BlsSignature,
}

/// Two conflicting votes that prove their common signers broke a Casper FFG rule.
pub trait SlashingEvidence {
    /// The two votes, in the order the evidence lists them.
    fn votes(&self) -> [IndexedVote<'_>; 2];

    /// The two votes as the fork choice reads them.
    fn conflicting_votes(&self) -> ConflictingVotes;

    /// Validators that signed both votes, in increasing order.
    fn common_signers(&self) -> Vec<ValidatorIndex> {
        let [first, second] = self.votes();
        let mut common: Vec<ValidatorIndex> = first
            .indices
            .iter()
            .filter(|index| second.indices.contains(index))
            .copied()
            .collect();
        common.sort_unstable();
        common.dedup();
        common
    }
}

/// Evidence a slasher found, in no fork's container, checked as gossip would before it spreads.
impl SlashingEvidence for ConflictingVotes {
    fn votes(&self) -> [IndexedVote<'_>; 2] {
        [&self.first, &self.second].map(|vote| IndexedVote {
            indices: &vote.indices,
            data: &vote.data,
            signature: &vote.signature,
        })
    }

    fn conflicting_votes(&self) -> ConflictingVotes {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, phase0::AttesterSlashing, vote::PayloadClaim};

    use super::*;

    #[test]
    fn a_fork_agnostic_vote_with_one_signer_names_its_attester() {
        // Fixture state: committee [v9, v4, v7], and bits 010 in committee 2.
        let committee = [ValidatorIndex(9), ValidatorIndex(4), ValidatorIndex(7)];
        let mut vote = CommitteeVote {
            data: AttestationData::default(),
            signature: BlsSignature::default(),
            committees: vec![CommitteeIndex(2)],
            bits: vec![false, true, false],
            payload: PayloadClaim::Silent,
        };

        assert_eq!(SubnetVote::committee_index(&vote), CommitteeIndex(2));
        assert_eq!(vote.attester(&committee), Ok(ValidatorIndex(4)));

        // Mutation: a second signer makes it an aggregate, no longer a subnet vote.
        vote.bits[2] = true;
        assert_eq!(
            vote.attester(&committee),
            Err(
                GossipError::reject("vote is not from one validator").with(Detail::Mismatch {
                    actual: 2,
                    expected: 1
                })
            )
        );
    }

    #[test]
    fn the_common_signers_are_the_sorted_intersection() {
        // Fixture state: votes signed by validators 1, 3, 5 and by 3, 4, 5.
        let mut slashing = AttesterSlashing::<Minimal>::default();
        for index in [1, 3, 5] {
            slashing
                .attestation_1
                .attesting_indices
                .push(ValidatorIndex(index))
                .unwrap();
        }
        for index in [3, 4, 5] {
            slashing
                .attestation_2
                .attesting_indices
                .push(ValidatorIndex(index))
                .unwrap();
        }

        assert_eq!(
            slashing.common_signers(),
            [ValidatorIndex(3), ValidatorIndex(5)]
        );
        assert_eq!(
            SlashingEvidence::common_signers(&slashing),
            [ValidatorIndex(3), ValidatorIndex(5)]
        );
    }
}
