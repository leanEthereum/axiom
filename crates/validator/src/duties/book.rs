//! The duties known for coming epochs, as the beacon node last reported them.

use std::collections::{BTreeMap, BTreeSet};

use axiom_beacon_json::api::{AttesterDuty, Duties, ProposerDuty, PtcDuty, SyncDuty};
use axiom_types::{BlsSignature, Epoch, Preset, Root, Slot};

/// A committee seat, with the proof that makes its holder an aggregator, if it is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttesterSeat {
    /// The seat.
    pub duty: AttesterDuty,
    /// The slot signature that selects the holder, when it aggregates.
    pub selection_proof: Option<BlsSignature>,
}

/// Every duty known for the current and next epochs.
///
/// Attester and proposer duties carry the root their shuffling depends on.
/// A refresh that reports another root replaces the epoch's duties, since a reorg moved them.
///
/// Proposer preferences are keyed by proposal slot and dependent root, as gossip keys them.
/// A slot whose root changes takes fresh preferences, signed over the new root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DutyBook {
    /// Proposers by epoch.
    proposers: BTreeMap<Epoch, Duties<ProposerDuty>>,
    /// Committee seats by epoch, with the root they depend on.
    attesters: BTreeMap<Epoch, (Root, Vec<AttesterSeat>)>,
    /// Sync committee seats by period.
    sync: BTreeMap<u64, Vec<SyncDuty>>,
    /// Payload timeliness seats by epoch.
    ptc: BTreeMap<Epoch, Vec<PtcDuty>>,
    /// Dependent roots whose proposer preferences were already published, by proposal slot.
    preferences: BTreeMap<Slot, BTreeSet<Root>>,
}

impl DutyBook {
    /// Records an epoch's proposers.
    pub fn set_proposers(&mut self, epoch: Epoch, duties: Duties<ProposerDuty>) {
        self.proposers.insert(epoch, duties);
    }

    /// An epoch's proposers, with their dependent root.
    #[must_use]
    pub fn proposers(&self, epoch: Epoch) -> Option<&Duties<ProposerDuty>> {
        self.proposers.get(&epoch)
    }

    /// The root an epoch's committee seats depend on, if known.
    #[must_use]
    pub fn attester_root(&self, epoch: Epoch) -> Option<Root> {
        self.attesters.get(&epoch).map(|(root, _)| *root)
    }

    /// Records an epoch's committee seats.
    pub fn set_attesters(&mut self, epoch: Epoch, root: Root, seats: Vec<AttesterSeat>) {
        self.attesters.insert(epoch, (root, seats));
    }

    /// The committee seats to vote from at a slot.
    #[must_use]
    pub fn attesters_at<P: Preset>(&self, slot: Slot) -> Vec<AttesterSeat> {
        self.attesters
            .get(&slot.epoch::<P>())
            .map(|(_, seats)| {
                seats
                    .iter()
                    .filter(|seat| seat.duty.slot == slot)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records a period's sync committee seats.
    pub fn set_sync(&mut self, period: u64, duties: Vec<SyncDuty>) {
        self.sync.insert(period, duties);
    }

    /// Whether a period's sync seats are known.
    #[must_use]
    pub fn has_sync(&self, period: u64) -> bool {
        self.sync.contains_key(&period)
    }

    /// The sync committee seats that sign at a slot.
    ///
    /// The message of a slot is included in the next block.
    /// So the committee of the next slot's period signs it.
    /// See `compute_sync_committee_period` and its use in the Altair validator spec.
    #[must_use]
    pub fn sync_at<P: Preset>(&self, slot: Slot) -> Vec<SyncDuty> {
        let period = (slot + 1).epoch::<P>().0 / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        self.sync.get(&period).cloned().unwrap_or_default()
    }

    /// Records an epoch's payload timeliness seats.
    pub fn set_ptc(&mut self, epoch: Epoch, duties: Vec<PtcDuty>) {
        self.ptc.insert(epoch, duties);
    }

    /// The payload timeliness seats that vote at a slot.
    #[must_use]
    pub fn ptc_at<P: Preset>(&self, slot: Slot) -> Vec<PtcDuty> {
        self.ptc
            .get(&slot.epoch::<P>())
            .map(|duties| {
                duties
                    .iter()
                    .filter(|duty| duty.slot == slot)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Committee seats this client holds in an epoch.
    #[must_use]
    pub fn attester_count(&self, epoch: Epoch) -> usize {
        self.attesters
            .get(&epoch)
            .map_or(0, |(_, seats)| seats.len())
    }

    /// Payload timeliness seats this client holds in an epoch.
    #[must_use]
    pub fn ptc_count(&self, epoch: Epoch) -> usize {
        self.ptc.get(&epoch).map_or(0, Vec::len)
    }

    /// Marks a slot's proposer preferences as published over a dependent root.
    ///
    /// Earlier roots stay marked until pruned, so a root a reorg brings back is not signed twice.
    /// See `validate_proposer_preferences_gossip` in the Gloas p2p spec.
    ///
    /// # Returns
    ///
    /// Whether they were not published over that root before.
    pub fn mark_preferences(&mut self, slot: Slot, dependent_root: Root) -> bool {
        self.preferences
            .entry(slot)
            .or_default()
            .insert(dependent_root)
    }

    /// Forgets everything before an epoch.
    pub fn prune<P: Preset>(&mut self, epoch: Epoch) {
        self.proposers = self.proposers.split_off(&epoch);
        self.attesters = self.attesters.split_off(&epoch);
        self.ptc = self.ptc.split_off(&epoch);
        let period = epoch.0 / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        self.sync = self.sync.split_off(&period);
        self.preferences = self.preferences.split_off(&epoch.start_slot::<P>());
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsPubkey, CommitteeIndex, Minimal, ValidatorIndex};

    use super::*;

    /// A seat of validator 1 at a slot.
    fn seat(slot: u64) -> AttesterSeat {
        AttesterSeat {
            duty: AttesterDuty {
                pubkey: BlsPubkey::ZERO,
                validator_index: ValidatorIndex(1),
                committee_index: CommitteeIndex(0),
                committee_length: 4,
                committees_at_slot: 1,
                validator_committee_index: 0,
                slot: Slot(slot),
            },
            selection_proof: None,
        }
    }

    #[test]
    fn seats_are_found_by_slot_and_pruned_by_epoch() {
        // Fixture state: minimal epochs of 8 slots; seats at slots 3 and 9.
        let mut book = DutyBook::default();
        book.set_attesters(Epoch(0), Root([1; 32]), vec![seat(3)]);
        book.set_attesters(Epoch(1), Root([2; 32]), vec![seat(9)]);
        assert_eq!(book.attesters_at::<Minimal>(Slot(3)), [seat(3)]);
        assert_eq!(book.attesters_at::<Minimal>(Slot(4)), []);

        // Pruning before epoch 1 keeps slot 9 only.
        book.prune::<Minimal>(Epoch(1));
        assert_eq!(book.attester_root(Epoch(0)), None);
        assert_eq!(book.attesters_at::<Minimal>(Slot(9)), [seat(9)]);
    }

    #[test]
    fn the_last_slot_of_a_period_signs_for_the_next_committee() {
        // Minimal periods last 8 epochs of 8 slots: slot 63 is the last of period 0.
        let mut book = DutyBook::default();
        let duty = |index| SyncDuty {
            pubkey: BlsPubkey::ZERO,
            validator_index: ValidatorIndex(index),
            validator_sync_committee_indices: vec![0],
        };
        book.set_sync(0, vec![duty(1)]);
        book.set_sync(1, vec![duty(2)]);
        assert_eq!(book.sync_at::<Minimal>(Slot(62)), [duty(1)]);
        assert_eq!(book.sync_at::<Minimal>(Slot(63)), [duty(2)]);
    }

    #[test]
    fn preferences_are_published_once_per_slot_and_dependent_root() {
        // Fixture state: minimal epochs of 8 slots; a proposal at slot 12, in epoch 1.
        // Its shuffling depends on the block at slot 7, first seen as root 0xaa.
        let mut book = DutyBook::default();
        assert!(book.mark_preferences(Slot(12), Root([0xaa; 32])));

        // A later refresh over the same root sends nothing new.
        assert!(!book.mark_preferences(Slot(12), Root([0xaa; 32])));

        // Mutation: a reorg replaces the block at slot 7 with root 0xbb.
        // Gossip keys preferences by slot and root, so the slot needs them again.
        assert!(book.mark_preferences(Slot(12), Root([0xbb; 32])));
        assert!(!book.mark_preferences(Slot(12), Root([0xbb; 32])));

        // The reorg reverting to 0xaa finds those preferences already sent.
        assert!(!book.mark_preferences(Slot(12), Root([0xaa; 32])));

        // Another slot over the same root is a separate proposal.
        assert!(book.mark_preferences(Slot(13), Root([0xbb; 32])));

        // Pruning before epoch 2 forgets every mark of epoch 1.
        book.prune::<Minimal>(Epoch(2));
        assert!(book.mark_preferences(Slot(12), Root([0xaa; 32])));
    }
}
