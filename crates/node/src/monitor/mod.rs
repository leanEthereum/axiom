//! The validator monitor: what the node sees of the validators its operator cares about.

mod metrics;
mod summary;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::Duration,
};

use axiom_fork_choice::Store;
use axiom_state_transition::{EpochVotes, State, VoteRecord};
use axiom_types::{
    BlsPubkey, Epoch, Preset, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    altair::{SyncCommitteeContribution, SyncCommitteeMessage},
    combined,
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
    phase0::{AttestationData, ProposerSlashing, VoluntaryExit},
    vote::{CommitteeVote, ConflictingVotes},
};
use tracing::{debug, error, info, warn};

pub(crate) use self::metrics::MonitorMetrics;
use self::summary::{EpochSummary, MonitoredValidator};
use crate::target_committees::TargetCommittees;

/// Watched validators past which metrics and logs cover only their total.
///
/// One series per validator and metric soon overwhelms a metrics server.
const DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD: usize = 64;

/// Epochs back from the clock that an imported block still describes current behaviour.
const RECENT_EPOCHS: u64 = 10;

/// Slots a missed proposal is given before it counts: a late block may still fill the slot.
const MISSED_BLOCK_LAG_SLOTS: u64 = 4;

/// The label of the metrics summed over every watched validator.
const TOTAL_LABEL: &str = "total";

/// Which validators the node watches, and how closely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorSettings {
    /// Whether every validator the node's validator clients subscribe for is watched too.
    pub auto_register: bool,
    /// Validators watched from the start, by key.
    pub pubkeys: Vec<BlsPubkey>,
    /// Past this many watched validators, metrics and logs cover only their total.
    pub individual_tracking_threshold: usize,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            auto_register: false,
            pubkeys: Vec::new(),
            individual_tracking_threshold: DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD,
        }
    }
}

/// Where the node saw a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// On a gossip topic.
    Gossip,
    /// Submitted to the beacon API.
    Api,
    /// Inside an imported block.
    Block,
}

impl Source {
    /// The value of the source label.
    const fn label(self) -> &'static str {
        match self {
            Self::Gossip => "gossip",
            Self::Api => "api",
            Self::Block => "block",
        }
    }
}

/// A message about validators, as the node saw it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Observed<'a, P: Preset> {
    /// A block, by its proposer.
    Block(&'a combined::SignedBeaconBlock<P>),
    /// One validator's vote, alone.
    Single {
        /// The voter.
        attester: ValidatorIndex,
        /// The vote.
        data: &'a AttestationData,
    },
    /// An aggregate of votes, by its aggregator.
    Aggregate {
        /// The validator that aggregated.
        aggregator: ValidatorIndex,
        /// The aggregated vote.
        vote: &'a CommitteeVote,
    },
    /// A sync committee member's signature.
    SyncMessage(&'a SyncCommitteeMessage),
    /// A sync subcommittee's aggregate, by its aggregator.
    Contribution {
        /// The validator that aggregated.
        aggregator: ValidatorIndex,
        /// The aggregated signatures.
        contribution: &'a SyncCommitteeContribution<P>,
    },
    /// A voluntary exit.
    Exit(&'a VoluntaryExit),
    /// Evidence of a proposer's double proposal.
    ProposerSlashing(&'a ProposerSlashing),
    /// Evidence of attesters' conflicting votes.
    AttesterSlashing(&'a ConflictingVotes),
}

/// Per-validator tracking for the validators an operator names.
///
/// # Overview
///
/// The monitor follows each watched validator through the node's inputs:
///
/// - its blocks, votes, aggregates, and sync messages, from gossip and the API, with their delay,
/// - their inclusion in aggregates and imported blocks,
/// - its exits and slashings,
/// - its proposals missed, from the slots its chain left empty,
/// - its balance and status, from each imported block's state,
/// - which parts of its votes the chain recorded right, once each epoch's record is final.
///
/// Everything goes to metrics under the names dashboards already read, and to the logs.
/// Past a threshold of watched validators, only totals are kept, to bound metric cardinality.
///
/// None of this is consensus data: a lost observation only skews a metric.
#[derive(Debug)]
pub(crate) struct ValidatorMonitor {
    /// Watched validators, by key.
    validators: HashMap<BlsPubkey, MonitoredValidator>,
    /// Keys of the watched validators whose index is known.
    indices: HashMap<ValidatorIndex, BlsPubkey>,
    /// Registry entries already searched for watched keys.
    scanned: usize,
    /// Whether validators the node's clients subscribe for are watched.
    auto_register: bool,
    /// Watched validators past which only totals are tracked.
    threshold: usize,
    /// Proposals missed, by slot, parent, and proposer, until finality.
    missed_blocks: HashSet<(Slot, Root, ValidatorIndex)>,
    /// Proposers of recent epochs, slot by slot.
    proposers: BTreeMap<Epoch, Vec<ValidatorIndex>>,
    /// Committees of recent vote targets, to name signers.
    committees: TargetCommittees,
    /// The latest epoch whose vote records were reported.
    reported_votes: Option<Epoch>,
    /// The latest epoch whose summaries were published.
    published: Option<Epoch>,
    /// The exported metrics.
    metrics: MonitorMetrics,
}

impl ValidatorMonitor {
    /// A monitor watching the validators the settings name.
    pub(crate) fn new(settings: &MonitorSettings, metrics: MonitorMetrics) -> Self {
        let mut monitor = Self {
            validators: HashMap::new(),
            indices: HashMap::new(),
            scanned: 0,
            auto_register: settings.auto_register,
            threshold: settings.individual_tracking_threshold,
            missed_blocks: HashSet::new(),
            proposers: BTreeMap::new(),
            committees: TargetCommittees::default(),
            reported_votes: None,
            published: None,
            metrics,
        };
        for pubkey in &settings.pubkeys {
            monitor.watch(*pubkey, None);
        }
        monitor
    }

    /// A monitor watching nothing, whose metrics nothing exports.
    pub(crate) fn detached() -> Self {
        Self::new(&MonitorSettings::default(), MonitorMetrics::detached())
    }

    /// Whether validators local clients subscribe for are watched too.
    pub(crate) const fn registers_automatically(&self) -> bool {
        self.auto_register
    }

    /// Whether the monitor watches nothing, and never will without a subscription.
    pub(crate) fn is_idle(&self) -> bool {
        self.validators.is_empty() && !self.auto_register
    }

    /// Watches a validator a local client subscribed for, when automatic registration is on.
    pub(crate) fn auto_register(&mut self, index: ValidatorIndex, pubkey: BlsPubkey) {
        if self.auto_register {
            self.watch(pubkey, Some(index));
        }
    }

    /// Accounts for a message the node saw, when it concerns a watched validator.
    ///
    /// # Arguments
    ///
    /// - `head`: the head block, whose state names the sync committee.
    /// - `seen_ms`: when the node saw the message, for its delay.
    pub(crate) fn observe<P: Preset>(
        &mut self,
        store: &Store<P>,
        head: Root,
        observed: Observed<'_, P>,
        source: Source,
        seen_ms: u64,
    ) {
        if self.validators.is_empty() {
            return;
        }
        match observed {
            Observed::Block(_) | Observed::Single { .. } | Observed::SyncMessage(_) => {
                self.observe_duty(store, observed, source, seen_ms);
            }
            Observed::Aggregate { .. } | Observed::Contribution { .. } => {
                self.observe_aggregation(store, head, observed, source, seen_ms);
            }
            Observed::Exit(_) | Observed::ProposerSlashing(_) | Observed::AttesterSlashing(_) => {
                self.observe_offence(observed, source);
            }
        }
    }

    /// Accounts for an imported block: its state, the votes and signatures it includes, its operations.
    ///
    /// A block crossing into a new epoch also settles the vote records of an epoch.
    /// The parent's state holds them: no later block may include a vote of that epoch.
    pub(crate) fn on_block<P: Preset>(
        &mut self,
        store: &Store<P>,
        root: Root,
        block: &combined::SignedBeaconBlock<P>,
    ) {
        if self.is_idle() {
            return;
        }
        let slot = block.slot();
        // Blocks long past, as during sync, describe no current behaviour.
        if slot.epoch::<P>().0 + RECENT_EPOCHS < store.current_epoch().0 {
            return;
        }
        let Some(post) = store.block_state(&root) else {
            return;
        };
        self.process_state(post, store.finalized_checkpoint().epoch);
        if self.validators.is_empty() {
            return;
        }
        let message = block.message();
        let parent_slot = store
            .blocks()
            .get(&block.parent_root())
            .map_or_else(|| Slot(slot.0.saturating_sub(1)), |parent| parent.slot);
        for vote in message.committee_votes() {
            self.vote_in_block::<P>(store, &vote, parent_slot);
        }
        if let (Some(aggregate), Some(sync)) =
            (block.sync_aggregate(), post.beacon().sync_committees())
        {
            let signers: Vec<BlsPubkey> = sync
                .current_sync_committee()
                .pubkeys
                .iter()
                .zip(aggregate.sync_committee_bits.iter())
                .filter(|(_, signed)| *signed)
                .map(|(pubkey, _)| *pubkey)
                .collect();
            for pubkey in signers {
                self.credit_key(
                    &pubkey,
                    slot.epoch::<P>(),
                    |metrics, label| {
                        metrics
                            .message
                            .sync_committee_message_in_block
                            .with_label_values([Source::Block.label(), label])
                            .inc();
                    },
                    |summary| summary.sync_signature_block_inclusions += 1,
                );
            }
        }
        // Operations inside a block have no delay to measure.
        for exit in message.voluntary_exits() {
            self.observe(store, root, Observed::Exit(&exit.message), Source::Block, 0);
        }
        for slashing in message.proposer_slashings() {
            self.observe(
                store,
                root,
                Observed::ProposerSlashing(slashing),
                Source::Block,
                0,
            );
        }
        for votes in message.conflicting_votes() {
            self.observe(
                store,
                root,
                Observed::AttesterSlashing(&votes),
                Source::Block,
                0,
            );
        }
        self.settle_votes(store, block, post);
    }

    /// Publishes the summaries of the latest epoch whose votes all had time to be included.
    ///
    /// Timing: four slots into an epoch, the votes of the epoch before have had their chance.
    /// Until then the epoch before that is reported, so a dashboard sees no false misses.
    pub(crate) fn on_slot<P: Preset>(&mut self, slot: Slot) {
        let epoch = slot.epoch::<P>().0;
        let settled = if slot.index_in_epoch::<P>() > P::MIN_ATTESTATION_INCLUSION_DELAY + 3 {
            epoch.checked_sub(1)
        } else {
            epoch.checked_sub(2)
        };
        let Some(previous) = settled.map(Epoch) else {
            return;
        };
        if self
            .published
            .is_some_and(|published| published >= previous)
        {
            return;
        }
        self.published = Some(previous);
        for validator in self.validators.values() {
            if let Some(summary) = validator.summary(previous) {
                self.publish_summary(&validator.label(), summary);
            }
        }
    }

    /// Accounts for a validator's own duty message: a block, a vote, or a sync message.
    fn observe_duty<P: Preset>(
        &mut self,
        store: &Store<P>,
        observed: Observed<'_, P>,
        source: Source,
        seen_ms: u64,
    ) {
        let config = store.config();
        let clock = store.slot_clock();
        // Delay past a component of the slot, zero for its start.
        let late = |slot: Slot, bps: u64| {
            seen_ms.saturating_sub(clock.slot_start_ms(slot) + clock.component_ms(bps))
        };
        let src = source.label();
        match observed {
            Observed::Block(block) => {
                let slot = block.slot();
                let delay = late(slot, 0);
                let proposer = block.message().proposer_index();
                let credited = self.credit(
                    proposer,
                    slot.epoch::<P>(),
                    |metrics, label| {
                        metrics
                            .message
                            .beacon_block
                            .with_label_values([src, label])
                            .inc();
                        metrics
                            .message
                            .beacon_block_delay
                            .with_label_values([src, label])
                            .observe(Self::seconds(delay));
                    },
                    |summary| summary.block(delay),
                );
                if let Some(validator) = credited {
                    info!(%slot, root = %block.block_root(), delay_ms = delay, src, %validator, "block from monitored validator");
                }
            }
            Observed::Single { attester, data } => {
                let delay = late(data.slot, 0);
                self.credit(
                    attester,
                    data.slot.epoch::<P>(),
                    |metrics, label| {
                        metrics
                            .message
                            .unaggregated_attestation
                            .with_label_values([src, label])
                            .inc();
                        metrics
                            .message
                            .unaggregated_attestation_delay
                            .with_label_values([src, label])
                            .observe(Self::seconds(delay));
                    },
                    |summary| summary.attestation(delay),
                );
            }
            Observed::SyncMessage(message) => {
                let epoch = message.slot.epoch::<P>();
                let due = config.sync_message_due_bps(config.fork_at(epoch));
                let delay = late(message.slot, due);
                self.credit(
                    message.validator_index,
                    epoch,
                    |metrics, label| {
                        metrics
                            .message
                            .sync_committee_messages
                            .with_label_values([src, label])
                            .inc();
                        metrics
                            .message
                            .sync_committee_messages_delay
                            .with_label_values([src, label])
                            .observe(Self::seconds(delay));
                    },
                    |summary| summary.sync_committee_message(delay),
                );
            }
            Observed::Aggregate { .. }
            | Observed::Contribution { .. }
            | Observed::Exit(_)
            | Observed::ProposerSlashing(_)
            | Observed::AttesterSlashing(_) => {}
        }
    }

    /// Accounts for an aggregation: its aggregator, and the validators it counts.
    fn observe_aggregation<P: Preset>(
        &mut self,
        store: &Store<P>,
        head: Root,
        observed: Observed<'_, P>,
        source: Source,
        seen_ms: u64,
    ) {
        let config = store.config();
        let clock = store.slot_clock();
        // Delay past a component of the slot, zero for its start.
        let late = |slot: Slot, bps: u64| {
            seen_ms.saturating_sub(clock.slot_start_ms(slot) + clock.component_ms(bps))
        };
        let src = source.label();
        match observed {
            Observed::Aggregate { aggregator, vote } => {
                let data = &vote.data;
                let epoch = data.slot.epoch::<P>();
                let due = config.aggregate_due_bps(config.fork_at(epoch));
                let delay = late(data.slot, due);
                self.credit(
                    aggregator,
                    epoch,
                    |metrics, label| {
                        metrics
                            .message
                            .aggregated_attestation
                            .with_label_values([src, label])
                            .inc();
                        metrics
                            .message
                            .aggregated_attestation_delay
                            .with_label_values([src, label])
                            .observe(Self::seconds(delay));
                    },
                    |summary| summary.aggregate(delay),
                );
                for signer in self.committees.signers(store, vote).unwrap_or_default() {
                    self.credit(
                        signer,
                        epoch,
                        |metrics, label| {
                            metrics
                                .message
                                .attestation_in_aggregate
                                .with_label_values([src, label])
                                .inc();
                            metrics
                                .message
                                .attestation_in_aggregate_delay
                                .with_label_values([src, label])
                                .observe(Self::seconds(delay));
                        },
                        |summary| summary.attestation_aggregate_inclusions += 1,
                    );
                }
            }
            Observed::Contribution {
                aggregator,
                contribution,
            } => {
                let epoch = contribution.slot.epoch::<P>();
                let due = config.contribution_due_bps(config.fork_at(epoch));
                let delay = late(contribution.slot, due);
                self.credit(
                    aggregator,
                    epoch,
                    |metrics, label| {
                        metrics
                            .message
                            .sync_contributions
                            .with_label_values([src, label])
                            .inc();
                        metrics
                            .message
                            .sync_contributions_delay
                            .with_label_values([src, label])
                            .observe(Self::seconds(delay));
                    },
                    |summary| summary.sync_contribution(delay),
                );
                for pubkey in Self::contributors(store, head, contribution) {
                    self.credit_key(
                        &pubkey,
                        epoch,
                        |metrics, label| {
                            metrics
                                .message
                                .sync_committee_message_in_contribution
                                .with_label_values([src, label])
                                .inc();
                        },
                        |summary| summary.sync_signature_contribution_inclusions += 1,
                    );
                }
            }
            Observed::Block(_)
            | Observed::Single { .. }
            | Observed::SyncMessage(_)
            | Observed::Exit(_)
            | Observed::ProposerSlashing(_)
            | Observed::AttesterSlashing(_) => {}
        }
    }

    /// Accounts for an exit or a slashing, which the logs always report.
    fn observe_offence<P: Preset>(&mut self, observed: Observed<'_, P>, source: Source) {
        let src = source.label();
        match observed {
            Observed::Exit(exit) => {
                let credited = self.credit(
                    exit.validator_index,
                    exit.epoch,
                    |metrics, label| metrics.message.exit.with_label_values([src, label]).inc(),
                    |summary| summary.exits += 1,
                );
                if let Some(validator) = credited {
                    info!(epoch = %exit.epoch, src, %validator, "voluntary exit of monitored validator");
                }
            }
            Observed::ProposerSlashing(slashing) => {
                let header = &slashing.signed_header_1.message;
                let credited = self.credit(
                    header.proposer_index,
                    header.slot.epoch::<P>(),
                    |metrics, label| {
                        metrics
                            .message
                            .proposer_slashing
                            .with_label_values([src, label])
                            .inc();
                    },
                    |summary| summary.proposer_slashings += 1,
                );
                if let Some(validator) = credited {
                    error!(slot = %header.slot, src, %validator, "proposer slashing of monitored validator");
                }
            }
            Observed::AttesterSlashing(votes) => {
                let slot = votes.first.data.slot;
                for signer in votes.common_signers() {
                    let credited = self.credit(
                        signer,
                        slot.epoch::<P>(),
                        |metrics, label| {
                            metrics
                                .message
                                .attester_slashing
                                .with_label_values([src, label])
                                .inc();
                        },
                        |summary| summary.attester_slashings += 1,
                    );
                    if let Some(validator) = credited {
                        error!(%slot, src, %validator, "attester slashing of monitored validator");
                    }
                }
            }
            Observed::Block(_)
            | Observed::Single { .. }
            | Observed::Aggregate { .. }
            | Observed::SyncMessage(_)
            | Observed::Contribution { .. } => {}
        }
    }

    /// Publishes one validator's summary of a settled epoch.
    fn publish_summary(&self, label: &str, summary: &EpochSummary) {
        let individual = self.individual();
        let metrics = &self.metrics;

        let labels: &[&str] = if individual {
            &[TOTAL_LABEL, label]
        } else {
            &[TOTAL_LABEL]
        };
        let delays = [
            (
                &metrics.summary.attestations_min_delay,
                summary.attestation_min_delay,
            ),
            (
                &metrics.summary.beacon_blocks_min_delay,
                summary.block_min_delay,
            ),
            (
                &metrics.summary.aggregates_min_delay,
                summary.aggregate_min_delay,
            ),
            (
                &metrics.summary.sync_committee_messages_min_delay,
                summary.sync_committee_message_min_delay,
            ),
            (
                &metrics.summary.sync_contribution_min_delay,
                summary.sync_contribution_min_delay,
            ),
        ];
        for (histogram, delay) in delays {
            if let Some(delay) = delay {
                for label in labels {
                    histogram
                        .with_label_values([label])
                        .observe(Self::seconds(delay));
                }
            }
        }
        if !individual {
            return;
        }
        let counts = [
            (&metrics.summary.attestations, summary.attestations),
            (
                &metrics.summary.attestation_aggregate_inclusions,
                summary.attestation_aggregate_inclusions,
            ),
            (
                &metrics.summary.attestation_block_inclusions,
                summary.attestation_block_inclusions,
            ),
            (&metrics.summary.beacon_blocks, summary.blocks),
            (&metrics.summary.aggregates, summary.aggregates),
            (&metrics.summary.exits, summary.exits),
            (
                &metrics.summary.proposer_slashings,
                summary.proposer_slashings,
            ),
            (
                &metrics.summary.attester_slashings,
                summary.attester_slashings,
            ),
            (
                &metrics.summary.sync_committee_messages,
                summary.sync_committee_messages,
            ),
            (
                &metrics.summary.sync_contribution_inclusions,
                summary.sync_signature_contribution_inclusions,
            ),
            (
                &metrics.summary.sync_signature_block_inclusions,
                summary.sync_signature_block_inclusions,
            ),
            (
                &metrics.summary.sync_contributions,
                summary.sync_contributions,
            ),
        ];
        for (gauge, count) in counts {
            gauge.with_label_values([label]).set_count(count);
        }
        if let Some(distance) = summary.attestation_min_block_inclusion_distance {
            metrics
                .summary
                .attestation_block_min_inclusion_distance
                .with_label_values([label])
                .set_count(distance);
        }
    }

    /// Starts watching a validator, by key and maybe index.
    fn watch(&mut self, pubkey: BlsPubkey, index: Option<ValidatorIndex>) {
        let validator = self.validators.entry(pubkey).or_insert_with(|| {
            info!(%pubkey, "started monitoring validator");
            MonitoredValidator::new(pubkey, None)
        });
        if let Some(index) = index {
            validator.set_index(index);
            self.indices.insert(index, pubkey);
        }
        self.metrics
            .status
            .validators_total
            .set_count(self.validators.len() as u64);
    }

    /// Whether metrics and logs still track each validator, rather than only the total.
    fn individual(&self) -> bool {
        self.validators.len() <= self.threshold
    }

    /// Credits a watched validator, by index, with a metric update and a summary update.
    ///
    /// # Returns
    ///
    /// The validator's label, when it is watched.
    fn credit(
        &mut self,
        index: ValidatorIndex,
        epoch: Epoch,
        metric: impl Fn(&MonitorMetrics, &str),
        summary: impl FnOnce(&mut EpochSummary),
    ) -> Option<String> {
        let pubkey = *self.indices.get(&index)?;
        self.credit_key(&pubkey, epoch, metric, summary)
    }

    /// Credits a watched validator, by key, as the index form does.
    fn credit_key(
        &mut self,
        pubkey: &BlsPubkey,
        epoch: Epoch,
        metric: impl Fn(&MonitorMetrics, &str),
        summary: impl FnOnce(&mut EpochSummary),
    ) -> Option<String> {
        let individual = self.individual();
        let validator = self.validators.get_mut(pubkey)?;
        let label = validator.label();
        metric(&self.metrics, TOTAL_LABEL);
        if individual {
            metric(&self.metrics, &label);
        }
        validator.record(epoch, summary);
        Some(label)
    }

    /// Credits the signers of a vote an imported block includes.
    ///
    /// The distance counts from the vote's slot to the block's parent, plus one.
    /// Measuring to the parent ignores the empty slots just before the block.
    fn vote_in_block<P: Preset>(
        &mut self,
        store: &Store<P>,
        vote: &CommitteeVote,
        parent_slot: Slot,
    ) {
        let data = &vote.data;
        let distance = parent_slot.0.saturating_sub(data.slot.0) + 1;
        let excess = distance.saturating_sub(P::MIN_ATTESTATION_INCLUSION_DELAY);
        let individual = self.individual();
        for signer in self.committees.signers(store, vote).unwrap_or_default() {
            let credited = self.credit(
                signer,
                data.slot.epoch::<P>(),
                |metrics, label| {
                    metrics
                        .message
                        .attestation_in_block
                        .with_label_values([Source::Block.label(), label])
                        .inc();
                },
                |summary| summary.attestation_in_block(distance),
            );
            if let Some(label) = credited.filter(|_| individual) {
                self.metrics
                    .message
                    .attestation_in_block_delay_slots
                    .with_label_values([Source::Block.label(), &label])
                    .set_count(excess);
            }
        }
    }

    /// Reads a valid state: indices of watched keys, balances, statuses, proposers, missed slots.
    fn process_state<P: Preset>(&mut self, post: &State<P>, finalized: Epoch) {
        let beacon = post.beacon();
        let registry = beacon.validators();
        // Only entries not searched yet: a shorter branch's registry adds nothing.
        for index in self.scanned..registry.len() {
            let pubkey = registry[index].pubkey;
            if let Some(validator) = self.validators.get_mut(&pubkey) {
                let index = ValidatorIndex(index as u64);
                validator.set_index(index);
                self.indices.insert(index, pubkey);
            }
        }
        self.scanned = self.scanned.max(registry.len());

        let epoch = beacon.current_epoch();
        let individual = self.individual();
        let balances = beacon.balances();
        for (index, pubkey) in &self.indices {
            let at = index.as_usize();
            let (Some(record), Some(balance)) = (registry.get(at), balances.get(at)) else {
                continue;
            };
            if let Some(validator) = self.validators.get_mut(pubkey) {
                validator.record(epoch, |summary| summary.balance = Some(*balance));
            }
            if !individual {
                continue;
            }
            let label = index.0.to_string();
            let metrics = &self.metrics;
            let flag = |set: bool| u64::from(set);
            let values = [
                (&metrics.status.balance_gwei, balance.0),
                (
                    &metrics.status.effective_balance_gwei,
                    record.effective_balance.0,
                ),
                (&metrics.status.slashed, flag(record.slashed)),
                (&metrics.status.active, flag(record.is_active_at(epoch))),
                (&metrics.status.exited, flag(record.exit_epoch <= epoch)),
                (
                    &metrics.status.withdrawable,
                    flag(record.withdrawable_epoch <= epoch),
                ),
                (
                    &metrics.status.activation_eligibility_epoch,
                    record.activation_eligibility_epoch.0,
                ),
                (&metrics.status.activation_epoch, record.activation_epoch.0),
                (&metrics.status.exit_epoch, record.exit_epoch.0),
                (
                    &metrics.status.withdrawable_epoch,
                    record.withdrawable_epoch.0,
                ),
            ];
            for (gauge, value) in values {
                gauge.with_label_values([&label]).set_count(value);
            }
        }
        self.remember_proposers(post);
        self.find_missed_blocks::<P>(post);
        self.missed_blocks
            .retain(|(slot, _, _)| slot.epoch::<P>().0 + 1 >= finalized.0);
    }

    /// Keeps the proposers of the state's epoch, the first time a state of that epoch is seen.
    ///
    /// A state of an epoch elects every slot of it: the seed and the active set are the epoch's.
    fn remember_proposers<P: Preset>(&mut self, post: &State<P>) {
        let epoch = post.beacon().current_epoch();
        if self.proposers.contains_key(&epoch) {
            return;
        }
        let mut copy = post.clone();
        let mut proposers = Vec::with_capacity(P::SLOTS_PER_EPOCH as usize);
        for slot in (0..P::SLOTS_PER_EPOCH).map(|offset| epoch.start_slot::<P>() + offset) {
            *copy.beacon_mut().slot_mut() = slot;
            match copy.beacon_proposer_index() {
                Ok(proposer) => proposers.push(proposer),
                Err(error) => {
                    debug!(%epoch, %error, "no proposers for the monitor");
                    return;
                }
            }
        }
        self.proposers.insert(epoch, proposers);
        // The current and the previous epoch are all a missed slot can fall in.
        while self.proposers.len() > 3 {
            self.proposers.pop_first();
        }
    }

    /// Counts the proposals watched validators missed, from the empty slots of a state.
    ///
    /// A slot is empty when its block root repeats the slot before's.
    /// The search covers the previous epoch on, short of the last few slots, which a late block may still fill.
    fn find_missed_blocks<P: Preset>(&mut self, post: &State<P>) {
        let beacon = post.beacon();
        let start = beacon
            .current_epoch()
            .0
            .saturating_sub(1)
            .saturating_mul(P::SLOTS_PER_EPOCH);
        let end = beacon.slot().0.saturating_sub(MISSED_BLOCK_LAG_SLOTS);
        for slot in (start.max(1)..=end).map(Slot) {
            let (Some(root), Some(parent)) = (
                beacon.block_root_at_slot(slot),
                beacon.block_root_at_slot(Slot(slot.0 - 1)),
            ) else {
                continue;
            };
            if root != parent {
                continue;
            }
            let proposer = self
                .proposers
                .get(&slot.epoch::<P>())
                .and_then(|proposers| proposers.get(slot.index_in_epoch::<P>() as usize))
                .copied();
            let Some(proposer) = proposer.filter(|proposer| self.indices.contains_key(proposer))
            else {
                continue;
            };
            if !self.missed_blocks.insert((slot, parent, proposer)) {
                continue;
            }
            let label = proposer.0.to_string();
            let individual = self.individual();
            self.metrics
                .record
                .missed_blocks
                .with_label_values([TOTAL_LABEL])
                .inc();
            if individual {
                self.metrics
                    .record
                    .missed_blocks
                    .with_label_values([&label])
                    .inc();
            }
            error!(%slot, %parent, validator = %label, "monitored validator missed a block");
        }
    }

    /// Reports the final vote records of an epoch, once, when a block enters a new epoch.
    fn settle_votes<P: Preset>(
        &mut self,
        store: &Store<P>,
        block: &combined::SignedBeaconBlock<P>,
        post: &State<P>,
    ) {
        let Some(parent) = store.block_state(&block.parent_root()) else {
            return;
        };
        let beacon = parent.beacon();
        // At genesis the previous epoch is the current one, whose votes are still to come.
        if beacon.current_epoch() >= block.slot().epoch::<P>()
            || beacon.previous_epoch() == beacon.current_epoch()
        {
            return;
        }
        let mut parent = parent.clone();
        let votes = match parent.previous_epoch_votes() {
            Ok(votes) => votes,
            Err(error) => {
                warn!(%error, "no vote records for the monitor");
                return;
            }
        };
        if self
            .reported_votes
            .is_some_and(|reported| reported >= votes.epoch)
        {
            return;
        }
        self.reported_votes = Some(votes.epoch);
        self.report_votes::<P>(&votes, post);
    }

    /// Counts the hits and misses of each watched validator's vote of an epoch.
    ///
    /// A vote with any part right counts as included: before Altair, any included vote does.
    fn report_votes<P: Preset>(&self, votes: &EpochVotes, post: &State<P>) {
        let individual = self.individual();
        let committee: HashSet<BlsPubkey> = post
            .beacon()
            .sync_committees()
            .map(|sync| {
                sync.current_sync_committee()
                    .pubkeys
                    .iter()
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        let mut included = Vec::new();
        let mut missing = Vec::new();
        let mut wrong_head = Vec::new();
        let mut wrong_target = Vec::new();
        for (index, pubkey) in &self.indices {
            let Some(VoteRecord::Owed(vote)) = votes.of(*index) else {
                continue;
            };
            let Some(validator) = self.validators.get(pubkey) else {
                continue;
            };
            let label = validator.label();
            let labels: &[&str] = if individual {
                &[TOTAL_LABEL, &label]
            } else {
                &[TOTAL_LABEL]
            };
            let metrics = &self.metrics;
            let any = vote.source || vote.target || vote.head;
            let counters = [
                if any {
                    &metrics.record.on_chain_attester_hit
                } else {
                    &metrics.record.on_chain_attester_miss
                },
                if vote.head {
                    &metrics.record.on_chain_head_attester_hit
                } else {
                    &metrics.record.on_chain_head_attester_miss
                },
                if vote.target {
                    &metrics.record.on_chain_target_attester_hit
                } else {
                    &metrics.record.on_chain_target_attester_miss
                },
            ];
            for counter in counters {
                for label in labels {
                    counter.with_label_values([label]).inc();
                }
            }
            if any {
                included.push(label.clone());
            } else {
                missing.push(label.clone());
            }
            if !vote.head {
                wrong_head.push(label.clone());
            }
            if !vote.target {
                wrong_target.push(label.clone());
            }
            if individual {
                let distance = vote.inclusion_delay.or_else(|| {
                    validator
                        .summary(votes.epoch)
                        .and_then(|summary| summary.attestation_min_block_inclusion_distance)
                });
                if let Some(distance) = distance {
                    metrics
                        .record
                        .on_chain_inclusion_distance
                        .with_label_values([&label])
                        .set_count(distance);
                }
                metrics
                    .record
                    .in_current_sync_committee
                    .with_label_values([&label])
                    .set_count(u64::from(committee.contains(pubkey)));
            }
        }
        let epoch = votes.epoch;
        if !included.is_empty() {
            info!(%epoch, validators = ?included, "previous epoch attestations included");
        }
        if !missing.is_empty() {
            info!(%epoch, validators = ?missing, "previous epoch attestations missing");
        }
        if !wrong_head.is_empty() {
            info!(%epoch, validators = ?wrong_head, "previous epoch attestations missed the head");
        }
        if !wrong_target.is_empty() {
            info!(%epoch, validators = ?wrong_target, "previous epoch attestations missed the target");
        }
    }

    /// The keys of the sync subcommittee members a contribution counts.
    ///
    /// Members come from the head state's current sync committee, in subcommittee order.
    fn contributors<P: Preset>(
        store: &Store<P>,
        head: Root,
        contribution: &SyncCommitteeContribution<P>,
    ) -> Vec<BlsPubkey> {
        let Some(sync) = store
            .block_state(&head)
            .and_then(|state| state.beacon().sync_committees())
        else {
            return Vec::new();
        };
        let size = (P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT) as usize;
        let start = contribution.subcommittee_index as usize * size;
        let pubkeys = &sync.current_sync_committee().pubkeys;
        contribution
            .aggregation_bits
            .iter()
            .enumerate()
            .filter(|(_, signed)| *signed)
            .filter_map(|(position, _)| pubkeys.get(start + position).copied())
            .collect()
    }

    /// Milliseconds as the seconds histograms take.
    const fn seconds(milliseconds: u64) -> f64 {
        Duration::from_millis(milliseconds).as_secs_f64()
    }
}
