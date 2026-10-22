//! What the node saw of one watched validator, epoch by epoch.

use std::collections::BTreeMap;

use axiom_types::{BlsPubkey, Epoch, Gwei, ValidatorIndex};

/// Epochs of history kept per validator.
///
/// Ten epochs outlast the inclusion window of any vote, so the summaries of interest are kept.
const HISTORIC_EPOCHS: usize = 10;

/// What the node saw of one validator in one epoch.
///
/// Delays are in milliseconds past each message's due time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EpochSummary {
    /// Single votes seen.
    pub(crate) attestations: u64,
    /// Earliest single vote.
    pub(crate) attestation_min_delay: Option<u64>,
    /// Aggregates holding the validator's vote.
    pub(crate) attestation_aggregate_inclusions: u64,
    /// Blocks holding the validator's vote.
    pub(crate) attestation_block_inclusions: u64,
    /// Smallest distance, in slots, between a vote and a block holding it.
    pub(crate) attestation_min_block_inclusion_distance: Option<u64>,
    /// Blocks proposed.
    pub(crate) blocks: u64,
    /// Earliest block.
    pub(crate) block_min_delay: Option<u64>,
    /// Aggregates sent.
    pub(crate) aggregates: u64,
    /// Earliest aggregate.
    pub(crate) aggregate_min_delay: Option<u64>,
    /// Sync committee messages seen.
    pub(crate) sync_committee_messages: u64,
    /// Earliest sync committee message.
    pub(crate) sync_committee_message_min_delay: Option<u64>,
    /// Blocks holding the validator's sync signature.
    pub(crate) sync_signature_block_inclusions: u64,
    /// Contributions holding the validator's sync signature.
    pub(crate) sync_signature_contribution_inclusions: u64,
    /// Contributions sent.
    pub(crate) sync_contributions: u64,
    /// Earliest contribution.
    pub(crate) sync_contribution_min_delay: Option<u64>,
    /// Voluntary exits seen.
    pub(crate) exits: u64,
    /// Proposer slashings seen.
    pub(crate) proposer_slashings: u64,
    /// Attester slashings seen.
    pub(crate) attester_slashings: u64,
    /// The validator's balance, as of the latest state of the epoch.
    pub(crate) balance: Option<Gwei>,
}

impl EpochSummary {
    /// Keeps the smaller of a recorded minimum and a new value.
    fn keep_min(current: &mut Option<u64>, new: u64) {
        *current = Some(current.map_or(new, |known| known.min(new)));
    }

    /// Counts a block, with its delay.
    pub(crate) fn block(&mut self, delay_ms: u64) {
        self.blocks += 1;
        Self::keep_min(&mut self.block_min_delay, delay_ms);
    }

    /// Counts a single vote, with its delay.
    pub(crate) fn attestation(&mut self, delay_ms: u64) {
        self.attestations += 1;
        Self::keep_min(&mut self.attestation_min_delay, delay_ms);
    }

    /// Counts an aggregate the validator sent, with its delay.
    pub(crate) fn aggregate(&mut self, delay_ms: u64) {
        self.aggregates += 1;
        Self::keep_min(&mut self.aggregate_min_delay, delay_ms);
    }

    /// Counts a sync committee message, with its delay.
    pub(crate) fn sync_committee_message(&mut self, delay_ms: u64) {
        self.sync_committee_messages += 1;
        Self::keep_min(&mut self.sync_committee_message_min_delay, delay_ms);
    }

    /// Counts a contribution the validator sent, with its delay.
    pub(crate) fn sync_contribution(&mut self, delay_ms: u64) {
        self.sync_contributions += 1;
        Self::keep_min(&mut self.sync_contribution_min_delay, delay_ms);
    }

    /// Counts a block holding the validator's vote, at a distance from the vote.
    pub(crate) fn attestation_in_block(&mut self, distance: u64) {
        self.attestation_block_inclusions += 1;
        Self::keep_min(&mut self.attestation_min_block_inclusion_distance, distance);
    }
}

/// One watched validator: its key, its index once known, and its recent epochs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MonitoredValidator {
    /// The validator's key.
    pubkey: BlsPubkey,
    /// The validator's index, once a state names it.
    index: Option<ValidatorIndex>,
    /// What was seen, by epoch, the oldest pruned first.
    summaries: BTreeMap<Epoch, EpochSummary>,
}

impl MonitoredValidator {
    /// A validator known by its key, and maybe its index.
    pub(crate) const fn new(pubkey: BlsPubkey, index: Option<ValidatorIndex>) -> Self {
        Self {
            pubkey,
            index,
            summaries: BTreeMap::new(),
        }
    }

    /// Records the validator's index, the first time a state names it.
    pub(crate) fn set_index(&mut self, index: ValidatorIndex) {
        self.index.get_or_insert(index);
    }

    /// The label of the validator's metrics: its index, or its key before the index is known.
    pub(crate) fn label(&self) -> String {
        self.index
            .map_or_else(|| self.pubkey.to_string(), |index| index.0.to_string())
    }

    /// Updates the summary of an epoch, keeping a bounded history.
    pub(crate) fn record(&mut self, epoch: Epoch, update: impl FnOnce(&mut EpochSummary)) {
        update(self.summaries.entry(epoch).or_default());
        while self.summaries.len() > HISTORIC_EPOCHS {
            self.summaries.pop_first();
        }
    }

    /// The summary of an epoch, when anything was seen in it.
    pub(crate) fn summary(&self, epoch: Epoch) -> Option<&EpochSummary> {
        self.summaries.get(&epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_summary_counts_and_keeps_the_earliest_delay() {
        let mut validator = MonitoredValidator::new(BlsPubkey([1; 48]), None);

        // Two blocks of epoch 3, 900 ms then 400 ms late: two counted, 400 kept.
        validator.record(Epoch(3), |summary| summary.block(900));
        validator.record(Epoch(3), |summary| summary.block(400));
        let summary = validator.summary(Epoch(3)).copied().unwrap();
        assert_eq!(
            summary,
            EpochSummary {
                blocks: 2,
                block_min_delay: Some(400),
                ..EpochSummary::default()
            }
        );
    }

    #[test]
    fn only_the_last_ten_epochs_are_kept() {
        let mut validator = MonitoredValidator::new(BlsPubkey([1; 48]), None);
        for epoch in 0..12 {
            validator.record(Epoch(epoch), |summary| summary.attestation(epoch));
        }

        // Epochs 0 and 1 fell out; 2 to 11 remain.
        assert_eq!(validator.summary(Epoch(1)), None);
        assert_eq!(
            validator
                .summary(Epoch(2))
                .map(|summary| summary.attestations),
            Some(1)
        );
        assert_eq!(validator.summaries.len(), 10);
    }

    #[test]
    fn the_label_is_the_index_once_known() {
        let mut validator = MonitoredValidator::new(BlsPubkey([0xab; 48]), None);
        assert_eq!(validator.label(), format!("0x{}", "ab".repeat(48)));

        // The first index sticks: a later one cannot move it.
        validator.set_index(ValidatorIndex(7));
        validator.set_index(ValidatorIndex(9));
        assert_eq!(validator.label(), "7");
    }
}
