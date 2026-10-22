//! What a node has already forwarded, so each message propagates once.

use std::collections::{HashMap, HashSet};

use axiom_types::{
    ColumnIndex, CommitteeIndex, Epoch, Preset, Root, Slot, SubnetId, ValidatorIndex,
};

/// Deduplication state of gossip validation.
///
/// Each set remembers the key that makes a message the first of its kind.
/// A later message with the same key is ignored, never rejected.
///
/// See `Seen` in the phase0 p2p spec, extended by later forks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Slot and proposer of every forwarded block.
    pub proposer_slots: HashSet<(Slot, ValidatorIndex)>,
    /// Target epoch and aggregator of every forwarded aggregate.
    pub aggregator_epochs: HashSet<(Epoch, ValidatorIndex)>,
    /// Participation bits of forwarded aggregates, by target epoch, data root, and committee.
    pub aggregate_data_roots: HashMap<(Epoch, Root, CommitteeIndex), Vec<Vec<bool>>>,
    /// Validators whose exit was forwarded.
    pub voluntary_exit_indices: HashSet<ValidatorIndex>,
    /// Proposers whose slashing was forwarded.
    pub proposer_slashing_indices: HashSet<ValidatorIndex>,
    /// Validators covered by a forwarded attester slashing.
    pub attester_slashing_indices: HashSet<ValidatorIndex>,
    /// Target epoch and attester of every forwarded single attestation.
    pub attestation_validator_epochs: HashSet<(Epoch, ValidatorIndex)>,
    /// Participation bits of forwarded contributions, by slot, block, and subcommittee.
    pub sync_contribution_data: HashMap<(Slot, Root, u64), Vec<Vec<bool>>>,
    /// Slot, aggregator, and subcommittee of every forwarded contribution.
    pub sync_contribution_aggregator_slots: HashSet<(Slot, ValidatorIndex, u64)>,
    /// Slot, validator, and subnet of every forwarded sync committee message.
    pub sync_message_validator_slots: HashSet<(Slot, ValidatorIndex, SubnetId)>,
    /// Validators whose credential change was forwarded.
    pub bls_to_execution_change_indices: HashSet<ValidatorIndex>,
    /// Slot, proposer, and column of every forwarded data column sidecar.
    pub data_column_sidecar_tuples: HashSet<(Slot, ValidatorIndex, ColumnIndex)>,
}

impl Seen {
    /// Forgets messages too old to propagate again.
    ///
    /// Votes and sidecars are gossiped only in the current and previous epochs.
    /// Older keys can never match a valid message, so dropping them keeps memory bounded.
    /// Keys by validator alone stay: an exit or slashing is forwarded once, ever.
    pub fn prune<P: Preset>(&mut self, current: Epoch) {
        // Keep the current and previous epochs, which the clock rules still accept.
        let oldest = Epoch(current.0.saturating_sub(1));
        let recent = |slot: Slot| slot.epoch::<P>() >= oldest;

        self.proposer_slots.retain(|(slot, _)| recent(*slot));
        self.aggregator_epochs.retain(|(epoch, _)| *epoch >= oldest);
        self.aggregate_data_roots
            .retain(|(epoch, _, _), _| *epoch >= oldest);
        self.attestation_validator_epochs
            .retain(|(epoch, _)| *epoch >= oldest);
        self.sync_contribution_data
            .retain(|(slot, _, _), _| recent(*slot));
        self.sync_contribution_aggregator_slots
            .retain(|(slot, _, _)| recent(*slot));
        self.sync_message_validator_slots
            .retain(|(slot, _, _)| recent(*slot));
        self.data_column_sidecar_tuples
            .retain(|(slot, _, _)| recent(*slot));
    }

    /// Whether some remembered bitfield covers every bit set in a new one.
    ///
    /// A new aggregate that adds no participant is redundant.
    /// See `is_non_strict_superset` in the phase0 p2p spec.
    #[must_use]
    pub fn is_covered(seen: &[Vec<bool>], bits: &[bool]) -> bool {
        seen.iter().any(|prior| {
            prior.len() == bits.len() && prior.iter().zip(bits).all(|(old, new)| *old || !*new)
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn pruning_keeps_the_current_and_previous_epochs_only() {
        // Fixture state: minimal epochs are 8 slots, the clock is in epoch 3.
        //
        //     slot 15  epoch 1   dropped
        //     slot 16  epoch 2   kept, previous epoch
        //     slot 24  epoch 3   kept, current epoch
        let mut seen = Seen::default();
        for slot in [15, 16, 24] {
            seen.proposer_slots.insert((Slot(slot), ValidatorIndex(0)));
        }
        seen.aggregator_epochs.insert((Epoch(1), ValidatorIndex(0)));
        seen.aggregator_epochs.insert((Epoch(2), ValidatorIndex(0)));
        seen.voluntary_exit_indices.insert(ValidatorIndex(9));

        seen.prune::<Minimal>(Epoch(3));

        let mut slots: Vec<u64> = seen.proposer_slots.iter().map(|(slot, _)| slot.0).collect();
        slots.sort_unstable();
        assert_eq!(slots, [16, 24]);
        assert_eq!(
            seen.aggregator_epochs,
            HashSet::from([(Epoch(2), ValidatorIndex(0))])
        );
        // An exit is remembered forever: a validator exits once.
        assert!(seen.voluntary_exit_indices.contains(&ValidatorIndex(9)));
    }
}
