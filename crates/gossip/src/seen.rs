//! What a node has already forwarded, so each message propagates once.

use std::collections::{HashMap, HashSet};

use axiom_ssz::Ssz;
use axiom_types::{
    BlobIndex, BuilderIndex, ColumnIndex, CommitteeIndex, Epoch, Gwei, Hash32, KzgCommitment,
    Preset, Root, Slot, SubnetId, ValidatorIndex, fulu::PartialDataColumnHeader,
    gloas::ProposerPreferences,
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
    /// Slot, proposer, and blob of every forwarded blob sidecar.
    pub blob_sidecar_tuples: HashSet<(Slot, ValidatorIndex, BlobIndex)>,
    /// The validated partial column header of each block, by block root.
    pub partial_data_column_headers: HashMap<Root, SeenPartialHeader>,
    /// Block root and column of every forwarded Gloas data column sidecar.
    pub data_column_sidecar_roots: HashSet<(Root, ColumnIndex)>,
    /// Gas limit of every payload whose envelope was forwarded, by the payload's block hash.
    ///
    /// A bid's gas limit must follow its parent payload's, which this records.
    pub execution_payloads: HashMap<Hash32, u64>,
    /// Block root and builder of every forwarded payload envelope.
    pub execution_payload_envelopes: HashSet<(Root, BuilderIndex)>,
    /// Slot and validator of every forwarded payload attestation.
    pub payload_attestation_validators: HashSet<(Slot, ValidatorIndex)>,
    /// Slot, parent payload, parent block, and builder of every forwarded bid.
    pub execution_payload_bids: HashSet<(Slot, Hash32, Root, BuilderIndex)>,
    /// The highest forwarded bid value for each slot, parent payload, and parent block.
    pub best_execution_payload_bid: HashMap<(Slot, Hash32, Root), Gwei>,
    /// Forwarded proposer preferences, by proposal slot and shuffling dependent root.
    pub proposer_preferences: HashMap<(Slot, Root), ProposerPreferences>,
}

/// What a validated partial column header tells about its block.
///
/// See `partial_data_column_headers` in the Fulu partial columns p2p spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeenPartialHeader {
    /// Root of the whole header, so a later header can be compared with it.
    pub root: Root,
    /// Slot of the header's block.
    pub slot: Slot,
    /// The block's blob commitments, which cells are checked against.
    pub commitments: Vec<KzgCommitment>,
}

impl SeenPartialHeader {
    /// What the seen state remembers of a validated header.
    #[must_use]
    pub fn of<P: Preset>(header: &PartialDataColumnHeader<P>) -> Self {
        Self {
            root: header.hash_tree_root(),
            slot: header.signed_block_header.message.slot,
            commitments: header.kzg_commitments.to_vec(),
        }
    }
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
        self.blob_sidecar_tuples
            .retain(|(slot, _, _)| recent(*slot));
        self.partial_data_column_headers
            .retain(|_, header| recent(header.slot));
        self.payload_attestation_validators
            .retain(|(slot, _)| recent(*slot));
        self.execution_payload_bids
            .retain(|(slot, _, _, _)| recent(*slot));
        self.best_execution_payload_bid
            .retain(|(slot, _, _), _| recent(*slot));
        self.proposer_preferences
            .retain(|(slot, _), _| recent(*slot));
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
