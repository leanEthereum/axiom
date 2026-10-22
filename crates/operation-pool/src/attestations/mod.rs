//! Attestations waiting for a block, aggregated per vote and committee.

mod committee;
mod vote;

use std::collections::{BTreeMap, HashMap};

use axiom_ssz::Ssz;
use axiom_types::{CommitteeIndex, Epoch, Preset, Root, phase0::AttestationData};
pub use committee::{CommitteeVotes, Insertion};
pub use vote::CommitteeAggregate;

use crate::{Aggregate, PoolError};

/// The aggregates of every committee that signed one attestation data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteGroup {
    /// The vote.
    pub data: AttestationData,
    /// Aggregates per committee, in committee order.
    pub committees: BTreeMap<CommitteeIndex, CommitteeVotes>,
}

/// Attestations seen on the network or submitted locally, until they are too old to include.
///
/// # Overview
///
/// Votes are grouped by the root of their data, then by committee.
/// A phase0 data names one committee, so its group holds one.
/// An Electra data names none, so its group gathers every committee of the slot.
///
/// That grouping is what lets one Electra block attestation span many committees.
/// See `compute_on_chain_aggregate` in the Electra validator spec.
///
/// # Invariants
///
/// Every aggregate's signature verifies: the caller checked each vote on entry.
/// Gossip rules check them, and so must any other entry point.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationPool {
    /// Groups by the root of their data.
    groups: HashMap<Root, VoteGroup>,
}

impl AttestationPool {
    /// Adds a vote whose signature the caller verified.
    ///
    /// # Errors
    ///
    /// Fails when the bits disagree with the committee's earlier votes, or a signature is no point.
    pub fn insert(&mut self, vote: CommitteeAggregate) -> Result<Insertion, PoolError> {
        let root = vote.data.hash_tree_root();
        let group = self.groups.entry(root).or_insert_with(|| VoteGroup {
            data: vote.data,
            committees: BTreeMap::new(),
        });
        group
            .committees
            .entry(vote.committee)
            .or_default()
            .insert(vote.aggregate)
    }

    /// The aggregate with the most signers for a data root and committee.
    ///
    /// Aggregators ask for it, to publish the best aggregate they can sign for.
    #[must_use]
    pub fn best_aggregate(
        &self,
        data_root: &Root,
        committee: CommitteeIndex,
    ) -> Option<(&AttestationData, &Aggregate)> {
        let group = self.groups.get(data_root)?;
        let best = group.committees.get(&committee)?.best()?;
        Some((&group.data, best))
    }

    /// Every group, in no particular order.
    pub fn groups(&self) -> impl Iterator<Item = &VoteGroup> {
        self.groups.values()
    }

    /// Number of stored aggregates, across every vote and committee.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups
            .values()
            .flat_map(|group| group.committees.values())
            .map(|votes| votes.aggregates().len())
            .sum()
    }

    /// Whether the pool holds no vote.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Drops votes no block from the current epoch on can include.
    ///
    /// A block includes votes targeting its own epoch or the one before.
    /// See `process_attestation` in the phase0 beacon chain spec.
    pub fn prune<P: Preset>(&mut self, current_epoch: Epoch) {
        let oldest = Epoch(current_epoch.0.saturating_sub(1));
        self.groups
            .retain(|_, group| group.data.slot.epoch::<P>() >= oldest);
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsSignature, Minimal, Slot};

    use super::*;
    use crate::Bits;

    /// A vote at a slot by one member of a committee of 4, with a placeholder signature.
    fn vote(slot: u64, committee: u64, position: usize) -> CommitteeAggregate {
        CommitteeAggregate {
            data: AttestationData {
                slot: Slot(slot),
                ..AttestationData::default()
            },
            committee: CommitteeIndex(committee),
            aggregate: Aggregate {
                bits: Bits::single(4, position),
                signature: BlsSignature::default(),
            },
        }
    }

    #[test]
    fn votes_group_by_data_then_committee() {
        // Fixture state: slot 9, committees 0 and 3 each send one new aggregate.
        let mut pool = AttestationPool::default();
        pool.insert(vote(9, 0, 1)).unwrap();
        pool.insert(vote(9, 3, 2)).unwrap();

        // One data group with two committees, two aggregates in all.
        assert_eq!(pool.groups().count(), 1);
        assert_eq!(pool.len(), 2);
        let root = vote(9, 0, 0).data.hash_tree_root();
        let (_, best) = pool.best_aggregate(&root, CommitteeIndex(3)).unwrap();
        assert_eq!(best.bits, Bits::single(4, 2));
        assert!(pool.best_aggregate(&root, CommitteeIndex(1)).is_none());
    }

    #[test]
    fn pruning_keeps_the_previous_and_current_epochs() {
        // Minimal epochs hold 8 slots: slot 7 is epoch 0, 8 is epoch 1, 16 is epoch 2.
        let mut pool = AttestationPool::default();
        for slot in [7, 8, 16] {
            pool.insert(vote(slot, 0, 0)).unwrap();
        }

        // At epoch 2, epoch 1 is the previous one and epoch 0 is gone.
        pool.prune::<Minimal>(Epoch(2));
        let mut slots: Vec<u64> = pool.groups().map(|group| group.data.slot.0).collect();
        slots.sort_unstable();
        assert_eq!(slots, [8, 16]);
    }
}
