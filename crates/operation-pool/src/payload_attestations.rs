//! Payload timeliness votes of Gloas, aggregated per vote over the slot's committee.

use std::{cmp::Reverse, collections::BTreeMap};

use axiom_ssz::{BitVector, Ssz};
use axiom_types::{
    Preset, Root, Slot, ValidatorIndex,
    gloas::{PayloadAttestation, PayloadAttestationData, PayloadAttestationMessage},
};

use crate::{Aggregate, Bits, CommitteeVotes, PoolError};

/// The aggregates of one payload vote.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PayloadVote {
    /// The vote.
    data: PayloadAttestationData,
    /// Its aggregates over the committee's seats.
    votes: CommitteeVotes,
}

/// Votes of payload timeliness committees, until the next block includes them.
///
/// # Overview
///
/// Each slot's committee votes on whether that slot's payload arrived in time.
/// The next block carries the votes on its parent, one aggregate per distinct vote.
/// A member sampled twice sets every seat it holds.
/// See the Gloas validator spec, section on payload attestations.
///
/// # Invariants
///
/// Every signature verifies: the caller checked each message on entry, as gossip rules do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttestationPool {
    /// Votes by slot, then by the root of their data.
    votes: BTreeMap<Slot, BTreeMap<Root, PayloadVote>>,
}

impl PayloadAttestationPool {
    /// Adds a member's vote at each of its seats in the slot's committee.
    ///
    /// # Errors
    ///
    /// Fails when the member holds no seat, or a signature is no point.
    pub fn insert(
        &mut self,
        message: &PayloadAttestationMessage,
        committee: &[ValidatorIndex],
    ) -> Result<(), PoolError> {
        let mut bits = Bits::zeros(committee.len());
        for (seat, member) in committee.iter().enumerate() {
            if *member == message.validator_index {
                bits.set(seat);
            }
        }
        if bits.is_zero() {
            return Err(PoolError::NotInPayloadCommittee {
                validator: message.validator_index,
                slot: message.data.slot,
            });
        }
        let data = &message.data;
        let vote = self
            .votes
            .entry(data.slot)
            .or_default()
            .entry(data.hash_tree_root())
            .or_insert_with(|| PayloadVote {
                data: data.clone(),
                votes: CommitteeVotes::default(),
            });
        vote.votes.insert(Aggregate {
            bits,
            signature: message.signature,
        })?;
        Ok(())
    }

    /// The aggregates a block on a parent block carries, the most signed first, at most a limit.
    ///
    /// Only votes on the parent, from the slot right before the block, count.
    /// See `process_payload_attestation` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the committee is larger than the preset allows.
    pub fn for_block<P: Preset>(
        &self,
        parent_slot: Slot,
        parent_root: Root,
        limit: usize,
    ) -> Result<Vec<PayloadAttestation<P>>, PoolError> {
        let Some(votes) = self.votes.get(&parent_slot) else {
            return Ok(Vec::new());
        };
        let mut chosen: Vec<(&PayloadAttestationData, &Aggregate)> = votes
            .values()
            .filter(|vote| vote.data.beacon_block_root == parent_root)
            .filter_map(|vote| vote.votes.best().map(|best| (&vote.data, best)))
            .collect();
        chosen.sort_by_key(|(_, best)| Reverse(best.bits.count_ones()));
        chosen.truncate(limit);
        chosen
            .into_iter()
            .map(|(data, best)| Self::attestation(data, best))
            .collect()
    }

    /// The best aggregate of every vote held, of one slot or of all, oldest slot first.
    ///
    /// See `getPoolPayloadAttestations` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when a committee is larger than the preset allows.
    pub fn pooled<P: Preset>(
        &self,
        slot: Option<Slot>,
    ) -> Result<Vec<PayloadAttestation<P>>, PoolError> {
        self.votes
            .iter()
            .filter(|(voted, _)| slot.is_none_or(|slot| **voted == slot))
            .flat_map(|(_, votes)| votes.values())
            .filter_map(|vote| vote.votes.best().map(|best| (&vote.data, best)))
            .map(|(data, best)| Self::attestation(data, best))
            .collect()
    }

    /// An aggregate of one vote, with its seats as the committee's bits.
    fn attestation<P: Preset>(
        data: &PayloadAttestationData,
        best: &Aggregate,
    ) -> Result<PayloadAttestation<P>, PoolError> {
        let mut aggregation_bits = BitVector::<P::PtcSize>::new();
        if best.bits.len() > aggregation_bits.len() {
            return Err(PoolError::TooManySigners {
                count: best.bits.len(),
                limit: aggregation_bits.len(),
            });
        }
        for seat in best.bits.ones() {
            aggregation_bits.set(seat, true);
        }
        Ok(PayloadAttestation {
            aggregation_bits,
            data: data.clone(),
            signature: best.signature,
        })
    }

    /// Drops votes older than the slot before a given one, which no block can use.
    pub fn prune(&mut self, current: Slot) {
        let oldest = Slot(current.0.saturating_sub(1));
        self.votes.retain(|slot, _| *slot >= oldest);
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::SecretKey;
    use axiom_types::{BlsSignature, Minimal};

    use super::*;

    /// A vote on the payload of slot 4's block, by a member holding a secret key.
    fn message(validator: u64, secret: u8, present: bool) -> PayloadAttestationMessage {
        let mut bytes = [0; 32];
        bytes[31] = secret;
        let key = SecretKey::from_bytes(&bytes).unwrap();
        PayloadAttestationMessage {
            validator_index: ValidatorIndex(validator),
            data: PayloadAttestationData {
                beacon_block_root: Root([4; 32]),
                slot: Slot(4),
                payload_present: present,
                blob_data_available: true,
            },
            signature: BlsSignature(key.sign(b"data").to_bytes()),
        }
    }

    #[test]
    fn votes_aggregate_per_vote_at_every_seat_of_their_member() {
        // Fixture state: the slot's committee of 4 seats is 3, 5, 3, 8; validator 3 sits twice.
        let committee = [3, 5, 3, 8].map(ValidatorIndex);
        let mut pool = PayloadAttestationPool::default();
        pool.insert(&message(3, 1, true), &committee).unwrap();
        pool.insert(&message(8, 2, true), &committee).unwrap();
        // Validator 5 saw no payload: another vote, its own aggregate.
        pool.insert(&message(5, 3, false), &committee).unwrap();

        let attestations = pool
            .for_block::<Minimal>(Slot(4), Root([4; 32]), 4)
            .unwrap();

        // The vote with three seats first, then the one with one.
        let seats: Vec<(bool, Vec<usize>)> = attestations
            .iter()
            .map(|attestation| {
                let seats = attestation
                    .aggregation_bits
                    .iter()
                    .enumerate()
                    .filter(|(_, bit)| *bit)
                    .map(|(seat, _)| seat)
                    .collect();
                (attestation.data.payload_present, seats)
            })
            .collect();
        assert_eq!(seats, [(true, vec![0, 2, 3]), (false, vec![1])]);

        // A block on another parent takes none of them.
        assert_eq!(
            pool.for_block::<Minimal>(Slot(4), Root([9; 32]), 4),
            Ok(Vec::new())
        );
    }

    #[test]
    fn the_pool_lists_its_best_aggregates_by_slot() {
        // Fixture state: a committee of seats 3 and 5; validator 3 votes at slot 4, 5 at slot 5.
        let committee = [3, 5].map(ValidatorIndex);
        let mut later = message(5, 2, false);
        later.data.slot = Slot(5);
        let mut pool = PayloadAttestationPool::default();
        pool.insert(&message(3, 1, true), &committee).unwrap();
        pool.insert(&later, &committee).unwrap();

        // Each vote comes back as one aggregate: seat 0 at slot 4, seat 1 at slot 5.
        let listed = |slot| {
            pool.pooled::<Minimal>(slot)
                .unwrap()
                .iter()
                .map(|attestation| {
                    let seats: Vec<usize> = attestation
                        .aggregation_bits
                        .iter()
                        .enumerate()
                        .filter(|(_, bit)| *bit)
                        .map(|(seat, _)| seat)
                        .collect();
                    (attestation.data.slot, seats)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(listed(None), [(Slot(4), vec![0]), (Slot(5), vec![1])]);
        assert_eq!(listed(Some(Slot(5))), [(Slot(5), vec![1])]);
        assert_eq!(listed(Some(Slot(6))), []);
    }

    #[test]
    fn a_vote_from_outside_the_committee_is_refused() {
        let committee = [3, 5].map(ValidatorIndex);
        assert_eq!(
            PayloadAttestationPool::default().insert(&message(7, 1, true), &committee),
            Err(PoolError::NotInPayloadCommittee {
                validator: ValidatorIndex(7),
                slot: Slot(4),
            })
        );
    }
}
