//! Votes reduced to the fields every fork shares, as the fork choice counts them.
//!
//! # Overview
//!
//! Phase0, Electra, and Gloas each define their own attestation and slashing containers.
//! They differ in how they name committees and bound their lists, not in what they vote.
//! Each container converts to a view here once, at the boundary.
//! Code past the boundary then reads one shape whatever the fork.

use std::collections::BTreeSet;

use crate::{BlsSignature, CommitteeIndex, ValidatorIndex, phase0::AttestationData};

/// What a vote says about the execution payload of the block it votes for.
///
/// Before Gloas a block carries its payload, so a vote says nothing about it.
/// From Gloas on, the data index of a vote states whether the voter saw the payload.
/// See `update_latest_messages` in the Gloas fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadClaim {
    /// The vote's fork does not let it speak about payloads.
    Silent,
    /// The voter did not see the payload, data index zero.
    Absent,
    /// The voter saw the payload, data index one.
    Present,
    /// The data index is neither zero nor one, which no Gloas vote may carry.
    Malformed(u64),
}

impl PayloadClaim {
    /// The claim a Gloas vote makes through its data index.
    ///
    /// See `validate_on_attestation` in the Gloas fork choice spec.
    #[must_use]
    pub const fn of_index(index: CommitteeIndex) -> Self {
        match index.0 {
            0 => Self::Absent,
            1 => Self::Present,
            other => Self::Malformed(other),
        }
    }
}

/// An aggregate vote from members of some committees of one slot.
///
/// The bits run across the named committees back to back, in committee order.
/// See `get_attesting_indices` in the phase0 and Electra beacon chain specs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeVote {
    /// The vote.
    pub data: AttestationData,
    /// Aggregate signature of every participant.
    pub signature: BlsSignature,
    /// The committees the bits cover, in increasing order.
    pub committees: Vec<CommitteeIndex>,
    /// Which committee members signed.
    pub bits: Vec<bool>,
    /// What the vote says about its head's payload.
    pub payload: PayloadClaim,
}

/// A vote with its signers listed by validator index.
///
/// See `IndexedAttestation` in the phase0 beacon chain spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedVote {
    /// The signers, sorted and unique in a valid vote.
    pub indices: Vec<ValidatorIndex>,
    /// The vote.
    pub data: AttestationData,
    /// Aggregate signature of the signers.
    pub signature: BlsSignature,
}

/// Two votes that the evidence claims break a Casper FFG rule together.
///
/// See `AttesterSlashing` in the phase0 beacon chain spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictingVotes {
    /// The first vote.
    pub first: IndexedVote,
    /// The second vote.
    pub second: IndexedVote,
}

impl ConflictingVotes {
    /// Validators that signed both votes, in increasing order.
    #[must_use]
    pub fn common_signers(&self) -> Vec<ValidatorIndex> {
        let second: BTreeSet<ValidatorIndex> = self.second.indices.iter().copied().collect();
        let common: BTreeSet<ValidatorIndex> = self
            .first
            .indices
            .iter()
            .copied()
            .filter(|index| second.contains(index))
            .collect();
        common.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(indices: &[u64]) -> IndexedVote {
        IndexedVote {
            indices: indices.iter().copied().map(ValidatorIndex).collect(),
            data: AttestationData::default(),
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn the_common_signers_are_the_sorted_intersection() {
        // Votes signed by validators 5, 3, 1 and by 3, 4, 5 share 3 and 5.
        let votes = ConflictingVotes {
            first: vote(&[5, 3, 1]),
            second: vote(&[3, 4, 5]),
        };
        assert_eq!(
            votes.common_signers(),
            [ValidatorIndex(3), ValidatorIndex(5)]
        );
    }

    #[test]
    fn a_gloas_index_claims_payload_presence() {
        // Index 0 saw no payload, index 1 saw it, index 2 is not a claim at all.
        assert_eq!(
            PayloadClaim::of_index(CommitteeIndex(0)),
            PayloadClaim::Absent
        );
        assert_eq!(
            PayloadClaim::of_index(CommitteeIndex(1)),
            PayloadClaim::Present
        );
        assert_eq!(
            PayloadClaim::of_index(CommitteeIndex(2)),
            PayloadClaim::Malformed(2)
        );
    }
}
