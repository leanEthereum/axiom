//! The aggregates of one committee for one vote.

use std::cmp::Reverse;

use crate::{Aggregate, PoolError};

/// How many distinct aggregates one committee keeps for one vote.
///
/// Honest aggregators number about 16 per committee, so their aggregates fit.
/// See `TARGET_AGGREGATORS_PER_COMMITTEE` in the phase0 validator spec.
const MAX_AGGREGATES: usize = 16;

/// What adding a committee's signers did to the stored aggregates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insertion {
    /// The signers joined an aggregate disjoint from them.
    Merged,
    /// The signers start an aggregate of their own.
    Added,
    /// An aggregate already holds every one of the signers.
    Known,
}

/// The aggregates of one committee for one vote, none a subset of another.
///
/// # Overview
///
/// Single votes join the first aggregate they are disjoint from.
/// That is naive aggregation: a vote adds its signature to an aggregate without that signer.
///
/// An aggregate covering another replaces it, since it pays at least as much in any block.
///
/// # Invariants
///
/// No stored aggregate is a subset of another.
/// At most a fixed number stay, the smallest dropped first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitteeVotes {
    /// The aggregates, in no particular order.
    aggregates: Vec<Aggregate>,
}

impl CommitteeVotes {
    /// Adds signers, merging them into a disjoint aggregate when one exists.
    ///
    /// # Errors
    ///
    /// Fails when the bits do not match the committee's length, or a signature is no point.
    pub fn insert(&mut self, incoming: Aggregate) -> Result<Insertion, PoolError> {
        if let Some(first) = self.aggregates.first()
            && first.bits.len() != incoming.bits.len()
        {
            return Err(PoolError::CommitteeLengthMismatch {
                expected: first.bits.len(),
                actual: incoming.bits.len(),
            });
        }
        if self
            .aggregates
            .iter()
            .any(|stored| stored.covers(&incoming))
        {
            return Ok(Insertion::Known);
        }

        // The largest disjoint aggregate grows, so the best one only ever improves.
        let disjoint = self
            .aggregates
            .iter_mut()
            .filter(|stored| stored.bits.is_disjoint(&incoming.bits))
            .max_by_key(|stored| stored.bits.count_ones());
        let insertion = match disjoint {
            Some(stored) => {
                stored.merge(&incoming)?;
                Insertion::Merged
            }
            None => {
                self.aggregates.push(incoming);
                Insertion::Added
            }
        };
        self.drop_covered();
        Ok(insertion)
    }

    /// The aggregates, none covering another.
    #[must_use]
    pub fn aggregates(&self) -> &[Aggregate] {
        &self.aggregates
    }

    /// The aggregate with the most signers.
    #[must_use]
    pub fn best(&self) -> Option<&Aggregate> {
        self.aggregates
            .iter()
            .max_by_key(|aggregate| aggregate.bits.count_ones())
    }

    /// Removes aggregates another one covers, then the smallest past the cap.
    fn drop_covered(&mut self) {
        // Largest first: an aggregate can only be covered by one at least as large.
        self.aggregates
            .sort_by_key(|aggregate| Reverse(aggregate.bits.count_ones()));
        let mut kept: Vec<Aggregate> = Vec::with_capacity(self.aggregates.len());
        for aggregate in self.aggregates.drain(..) {
            if !kept.iter().any(|larger| larger.covers(&aggregate)) {
                kept.push(aggregate);
            }
        }
        kept.truncate(MAX_AGGREGATES);
        self.aggregates = kept;
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::SecretKey;
    use axiom_types::BlsSignature;

    use super::*;
    use crate::Bits;

    /// A vote of the validator holding secret key k, at a position of a committee of 4.
    fn vote(secret: u8, positions: &[usize]) -> Aggregate {
        let mut bytes = [0; 32];
        bytes[31] = secret;
        let key = SecretKey::from_bytes(&bytes).unwrap();
        let mut bits = Bits::zeros(4);
        for position in positions {
            bits.set(*position);
        }
        Aggregate {
            bits,
            signature: BlsSignature(key.sign(b"data").to_bytes()),
        }
    }

    #[test]
    fn single_votes_merge_into_one_aggregate() {
        // Fixture state: a committee of 4; votes from positions 0, 2, and 3 arrive one by one.
        let mut votes = CommitteeVotes::default();
        assert_eq!(votes.insert(vote(1, &[0])), Ok(Insertion::Added));
        assert_eq!(votes.insert(vote(3, &[2])), Ok(Insertion::Merged));
        assert_eq!(votes.insert(vote(4, &[3])), Ok(Insertion::Merged));

        // One aggregate holds all three; the same vote again adds nothing.
        assert_eq!(votes.aggregates().len(), 1);
        assert_eq!(
            votes.best().unwrap().bits.ones().collect::<Vec<_>>(),
            [0, 2, 3]
        );
        assert_eq!(votes.insert(vote(3, &[2])), Ok(Insertion::Known));
    }

    #[test]
    fn an_overlapping_aggregate_is_kept_apart_and_a_covering_one_replaces_both() {
        // Fixture state: aggregates over positions {0, 1} and then {1, 2} overlap at 1.
        let mut votes = CommitteeVotes::default();
        votes.insert(vote(1, &[0, 1])).unwrap();
        assert_eq!(votes.insert(vote(2, &[1, 2])), Ok(Insertion::Added));
        assert_eq!(votes.aggregates().len(), 2);

        // Mutation: an aggregate over {0, 1, 2, 3} covers both, which leave.
        votes.insert(vote(5, &[0, 1, 2, 3])).unwrap();
        assert_eq!(votes.aggregates().len(), 1);
        assert_eq!(votes.best().unwrap().bits.count_ones(), 4);
    }

    #[test]
    fn bits_of_another_length_are_refused() {
        // A committee of 4 cannot take a vote with 5 bits.
        let mut votes = CommitteeVotes::default();
        votes.insert(vote(1, &[0])).unwrap();
        let mut long = vote(2, &[1]);
        long.bits = Bits::single(5, 1);

        assert_eq!(
            votes.insert(long),
            Err(PoolError::CommitteeLengthMismatch {
                expected: 4,
                actual: 5
            })
        );
    }
}
