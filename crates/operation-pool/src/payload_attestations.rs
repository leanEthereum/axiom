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
            .map(|(data, best)| {
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
            })
            .collect()
    }

    /// Drops votes older than the slot before a given one, which no block can use.
    pub fn prune(&mut self, current: Slot) {
        let oldest = Slot(current.0.saturating_sub(1));
        self.votes.retain(|slot, _| *slot >= oldest);
    }
}
