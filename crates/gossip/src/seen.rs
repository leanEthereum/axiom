//! What a node has already forwarded, so each message propagates once.

use std::collections::{HashMap, HashSet};

use axiom_types::{ColumnIndex, CommitteeIndex, Epoch, Root, Slot, SubnetId, ValidatorIndex};

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
    /// Participation bits of forwarded aggregates, by attestation data root and committee.
    pub aggregate_data_roots: HashMap<(Root, CommitteeIndex), Vec<Vec<bool>>>,
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
