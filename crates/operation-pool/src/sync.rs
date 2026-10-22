//! Sync committee signatures, aggregated per subcommittee into a block's sync aggregate.

use std::{collections::BTreeMap, marker::PhantomData};

use axiom_ssz::BitVector;
use axiom_types::{
    Preset, Root, Slot, ValidatorIndex,
    accessors::{CoreState, SyncCommitteeState},
    altair::{SyncAggregate, SyncCommitteeContribution, SyncCommitteeMessage},
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
};

use crate::{Aggregate, Bits, CommitteeVotes, Insertion, PoolError};

/// Signatures of the sync committee over block roots, by slot, root, and subcommittee.
///
/// # Overview
///
/// The sync committee splits into four subcommittees, one per gossip subnet.
/// Messages of single members aggregate naively within their subcommittee.
/// Contributions of aggregators join the same aggregates.
///
/// A block at slot s carries the signatures of slot s - 1 over its parent's root.
/// It joins the best aggregate of each subcommittee, back to back.
/// See `process_sync_aggregate` in the Altair beacon chain spec.
///
/// # Invariants
///
/// Every signature verifies: the caller checked each message on entry, as gossip rules do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncPool<P: Preset> {
    /// Aggregates by slot, signed root, and subcommittee.
    subcommittees: BTreeMap<(Slot, Root, u64), CommitteeVotes>,
    /// The preset fixing the committee's size.
    preset: PhantomData<P>,
}

impl<P: Preset> Default for SyncPool<P> {
    fn default() -> Self {
        Self {
            subcommittees: BTreeMap::new(),
            preset: PhantomData,
        }
    }
}

impl<P: Preset> SyncPool<P> {
    /// Members of each subcommittee.
    ///
    /// See `SYNC_COMMITTEE_SIZE` and `SYNC_COMMITTEE_SUBNET_COUNT` in the Altair specs.
    const SUBCOMMITTEE_SIZE: usize =
        (P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT) as usize;

    /// The seats a validator holds in a state's current sync committee.
    ///
    /// A validator may hold several seats, since members are sampled with replacement.
    /// See `get_next_sync_committee_indices` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator is unknown, or holds no seat.
    pub fn seats<S: CoreState + SyncCommitteeState>(
        state: &S,
        validator: ValidatorIndex,
    ) -> Result<Vec<usize>, PoolError> {
        let validators = state.validators();
        let record = validators
            .get(validator.as_usize())
            .ok_or(PoolError::UnknownValidator {
                index: validator,
                registry_size: validators.len(),
            })?;
        let seats: Vec<usize> = state
            .current_sync_committee()
            .pubkeys
            .iter()
            .enumerate()
            .filter(|(_, key)| **key == record.pubkey)
            .map(|(seat, _)| seat)
            .collect();
        if seats.is_empty() {
            return Err(PoolError::NotInSyncCommittee(validator));
        }
        Ok(seats)
    }

    /// Adds a member's message at each of its seats.
    ///
    /// # Errors
    ///
    /// Fails when a seat lies outside the committee, or a signature is no point.
    pub fn insert_message(
        &mut self,
        message: &SyncCommitteeMessage,
        seats: &[usize],
    ) -> Result<(), PoolError> {
        for seat in seats {
            let subcommittee = (seat / Self::SUBCOMMITTEE_SIZE) as u64;
            if subcommittee >= SYNC_COMMITTEE_SUBNET_COUNT {
                return Err(PoolError::TooManySigners {
                    count: seat + 1,
                    limit: P::SYNC_COMMITTEE_SIZE as usize,
                });
            }
            let aggregate = Aggregate {
                bits: Bits::single(Self::SUBCOMMITTEE_SIZE, seat % Self::SUBCOMMITTEE_SIZE),
                signature: message.signature,
            };
            self.subcommittees
                .entry((message.slot, message.beacon_block_root, subcommittee))
                .or_default()
                .insert(aggregate)?;
        }
        Ok(())
    }

    /// Adds an aggregator's contribution.
    ///
    /// # Errors
    ///
    /// Fails when the subcommittee does not exist, or a signature is no point.
    pub fn insert_contribution(
        &mut self,
        contribution: &SyncCommitteeContribution<P>,
    ) -> Result<Insertion, PoolError> {
        let subcommittee = contribution.subcommittee_index;
        if subcommittee >= SYNC_COMMITTEE_SUBNET_COUNT {
            return Err(PoolError::TooManySigners {
                count: subcommittee as usize + 1,
                limit: SYNC_COMMITTEE_SUBNET_COUNT as usize,
            });
        }
        let aggregate = Aggregate {
            bits: Bits::from_bools(contribution.aggregation_bits.iter()),
            signature: contribution.signature,
        };
        self.subcommittees
            .entry((
                contribution.slot,
                contribution.beacon_block_root,
                subcommittee,
            ))
            .or_default()
            .insert(aggregate)
    }

    /// The best contribution of a subcommittee, for an aggregator to publish.
    ///
    /// See `get_sync_committee_contribution` in the Altair validator spec.
    #[must_use]
    pub fn contribution(
        &self,
        slot: Slot,
        root: Root,
        subcommittee: u64,
    ) -> Option<SyncCommitteeContribution<P>> {
        let best = self
            .subcommittees
            .get(&(slot, root, subcommittee))?
            .best()?;
        let mut aggregation_bits = BitVector::<P::SyncSubcommitteeSize>::new();
        for position in best.bits.ones() {
            aggregation_bits.set(position, true);
        }
        Some(SyncCommitteeContribution {
            slot,
            beacon_block_root: root,
            subcommittee_index: subcommittee,
            aggregation_bits,
            signature: best.signature,
        })
    }

    /// The sync aggregate of a block whose parent is a root at a slot.
    ///
    /// Without any signature it is empty, with the point at infinity as its signature.
    ///
    /// # Errors
    ///
    /// Fails when the signatures do not aggregate.
    pub fn sync_aggregate(&self, slot: Slot, root: Root) -> Result<SyncAggregate<P>, PoolError> {
        let mut sync_committee_bits = BitVector::<P::SyncCommitteeSize>::new();
        let mut signatures = Vec::new();
        for subcommittee in 0..SYNC_COMMITTEE_SUBNET_COUNT {
            let best = self
                .subcommittees
                .get(&(slot, root, subcommittee))
                .and_then(CommitteeVotes::best);
            let Some(best) = best else {
                continue;
            };
            let offset = subcommittee as usize * Self::SUBCOMMITTEE_SIZE;
            for position in best.bits.ones() {
                sync_committee_bits.set(offset + position, true);
            }
            signatures.push(best.signature);
        }
        Ok(SyncAggregate {
            sync_committee_bits,
            sync_committee_signature: Aggregate::sum(&signatures)?,
        })
    }

    /// Drops signatures older than the slot before a given one, which no block can use.
    pub fn prune(&mut self, current: Slot) {
        let oldest = Slot(current.0.saturating_sub(1));
        self.subcommittees.retain(|(slot, _, _), _| *slot >= oldest);
    }

    /// Number of stored aggregates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subcommittees
            .values()
            .map(|votes| votes.aggregates().len())
            .sum()
    }

    /// Whether no signature is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subcommittees.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::{SecretKey, Signature};
    use axiom_types::{BlsSignature, Minimal};

    use super::*;

    /// A signature by secret key k over a fixed message.
    fn signed(secret: u8) -> BlsSignature {
        let mut bytes = [0; 32];
        bytes[31] = secret;
        BlsSignature(
            SecretKey::from_bytes(&bytes)
                .unwrap()
                .sign(b"root")
                .to_bytes(),
        )
    }

    #[test]
    fn messages_and_contributions_fill_the_block_aggregate() {
        // Fixture state: the minimal committee has 32 seats, 8 per subcommittee.
        // Seats 1 and 9 sign singly; subcommittee 3 sends a contribution of seats 24 and 31.
        let mut pool = SyncPool::<Minimal>::default();
        let (slot, root) = (Slot(5), Root([7; 32]));
        let message = |secret| SyncCommitteeMessage {
            slot,
            beacon_block_root: root,
            validator_index: ValidatorIndex(0),
            signature: signed(secret),
        };
        pool.insert_message(&message(1), &[1]).unwrap();
        pool.insert_message(&message(2), &[9]).unwrap();
        let mut contribution = SyncCommitteeContribution::<Minimal> {
            slot,
            beacon_block_root: root,
            subcommittee_index: 3,
            signature: signed(3),
            ..SyncCommitteeContribution::default()
        };
        contribution.aggregation_bits.set(0, true);
        contribution.aggregation_bits.set(7, true);
        pool.insert_contribution(&contribution).unwrap();

        let aggregate = pool.sync_aggregate(slot, root).unwrap();

        // Seats 1, 9, 24, and 31, and the three signatures summed.
        let seats: Vec<usize> = aggregate
            .sync_committee_bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit)
            .map(|(seat, _)| seat)
            .collect();
        assert_eq!(seats, [1, 9, 24, 31]);
        assert_eq!(
            aggregate.sync_committee_signature,
            Aggregate::sum(&[signed(1), signed(2), signed(3)]).unwrap()
        );
    }

    #[test]
    fn a_root_nobody_signed_gives_the_empty_aggregate() {
        let pool = SyncPool::<Minimal>::default();
        let aggregate = pool.sync_aggregate(Slot(5), Root([7; 32])).unwrap();
        assert_eq!(aggregate.sync_committee_bits.count_ones(), 0);
        assert_eq!(
            aggregate.sync_committee_signature,
            BlsSignature(Signature::INFINITY_BYTES)
        );
    }
}
