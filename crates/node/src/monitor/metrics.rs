//! The metrics of the validator monitor, under the names existing dashboards read.

use axiom_telemetry::{
    Buckets, CounterVec, Gauge, GaugeVec, HistogramVec, Registry, RegistryError,
};

/// Bucket bounds of every delay histogram, in seconds: the Prometheus client default.
///
/// Delays run from milliseconds to a few seconds, which these bounds cover.
const DELAY_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Every metric the validator monitor updates, in four groups.
///
/// A validator label is the validator's index, or its key before the index is known.
/// Its value is the word total for the sum over every watched validator.
/// A source label says where a message was seen: gossip, api, or block.
#[derive(Clone, Debug)]
pub(crate) struct MonitorMetrics {
    /// Balances and statuses.
    pub(crate) status: StatusMetrics,
    /// What the chain recorded.
    pub(crate) record: RecordMetrics,
    /// The latest settled epoch's summaries.
    pub(crate) summary: SummaryMetrics,
    /// Messages, by source.
    pub(crate) message: MessageMetrics,
}

/// The labels of the per-validator metrics.
const VALIDATOR: [&str; 1] = ["validator"];

/// The labels of the per-source, per-validator metrics.
const SOURCE_VALIDATOR: [&str; 2] = ["src", "validator"];

impl MonitorMetrics {
    /// Registers every monitor metric in a registry.
    ///
    /// # Errors
    ///
    /// Fails when a name is already taken in the registry.
    pub(crate) fn register(registry: &Registry) -> Result<Self, RegistryError> {
        // Invariant: the bounds are positive, finite, and strictly increasing literals.
        // Bucket validation only refuses other bounds, so it cannot fail here.
        let buckets = Buckets::new(&DELAY_BUCKETS).expect("the delay bounds are increasing");
        Ok(Self {
            status: StatusMetrics::register(registry, &buckets)?,
            record: RecordMetrics::register(registry, &buckets)?,
            summary: SummaryMetrics::register(registry, &buckets)?,
            message: MessageMetrics::register(registry, &buckets)?,
        })
    }

    /// Metrics in a registry of their own, which nothing exports.
    pub(crate) fn detached() -> Self {
        // Invariant: a fresh registry holds no names, and the set's own names are distinct.
        Self::register(&Registry::new()).expect("a fresh registry takes every monitor metric")
    }
}

/// The balance and status of each watched validator, from each imported block's state.
#[derive(Clone, Debug)]
pub(crate) struct StatusMetrics {
    /// Watched validators.
    pub(crate) validators_total: Gauge,

    /// Balance of each watched validator, in gwei.
    pub(crate) balance_gwei: GaugeVec<1>,

    /// Effective balance of each watched validator, in gwei.
    pub(crate) effective_balance_gwei: GaugeVec<1>,

    /// One when the validator is slashed.
    pub(crate) slashed: GaugeVec<1>,

    /// One when the validator is active.
    pub(crate) active: GaugeVec<1>,

    /// One when the validator has exited.
    pub(crate) exited: GaugeVec<1>,

    /// One when the validator may withdraw.
    pub(crate) withdrawable: GaugeVec<1>,

    /// Epoch the validator became eligible for activation.
    pub(crate) activation_eligibility_epoch: GaugeVec<1>,

    /// Epoch the validator activates.
    pub(crate) activation_epoch: GaugeVec<1>,

    /// Epoch the validator exits.
    pub(crate) exit_epoch: GaugeVec<1>,

    /// Epoch the validator may withdraw.
    pub(crate) withdrawable_epoch: GaugeVec<1>,
}

impl StatusMetrics {
    /// Registers the group in a registry.
    fn register(registry: &Registry, _buckets: &Buckets) -> Result<Self, RegistryError> {
        let gauge = |name: &str, help: &str| registry.gauge_vec(name, help, VALIDATOR);
        Ok(Self {
            validators_total: registry.gauge(
                "validator_monitor_validators_total",
                "Validators this node monitors.",
            )?,
            balance_gwei: gauge("validator_monitor_balance_gwei", "Balance in gwei.")?,
            effective_balance_gwei: gauge(
                "validator_monitor_effective_balance_gwei",
                "Effective balance in gwei.",
            )?,
            slashed: gauge("validator_monitor_slashed", "One if slashed.")?,
            active: gauge("validator_monitor_active", "One if active.")?,
            exited: gauge("validator_monitor_exited", "One if exited.")?,
            withdrawable: gauge("validator_monitor_withdrawable", "One if withdrawable.")?,
            activation_eligibility_epoch: gauge(
                "validator_activation_eligibility_epoch",
                "Epoch of eligibility for activation.",
            )?,
            activation_epoch: gauge("validator_activation_epoch", "Epoch of activation.")?,
            exit_epoch: gauge("validator_exit_epoch", "Epoch of exit.")?,
            withdrawable_epoch: gauge(
                "validator_withdrawable_epoch",
                "Epoch the balance becomes withdrawable.",
            )?,
        })
    }
}

/// What the chain recorded of each watched validator: votes, proposals, sync duty.
#[derive(Clone, Debug)]
pub(crate) struct RecordMetrics {
    /// Previous epoch votes the chain recorded with any part right.
    pub(crate) on_chain_attester_hit: CounterVec<1>,

    /// Previous epoch votes the chain recorded with no part right, or not at all.
    pub(crate) on_chain_attester_miss: CounterVec<1>,

    /// Previous epoch votes with the head right.
    pub(crate) on_chain_head_attester_hit: CounterVec<1>,

    /// Previous epoch votes without the head right.
    pub(crate) on_chain_head_attester_miss: CounterVec<1>,

    /// Previous epoch votes with the target right.
    pub(crate) on_chain_target_attester_hit: CounterVec<1>,

    /// Previous epoch votes without the target right.
    pub(crate) on_chain_target_attester_miss: CounterVec<1>,

    /// Inclusion distance of the previous epoch vote.
    pub(crate) on_chain_inclusion_distance: GaugeVec<1>,

    /// One when the validator sits in the current sync committee.
    pub(crate) in_current_sync_committee: GaugeVec<1>,

    /// Proposals the validator missed.
    pub(crate) missed_blocks: CounterVec<1>,
}

impl RecordMetrics {
    /// Registers the group in a registry.
    fn register(registry: &Registry, _buckets: &Buckets) -> Result<Self, RegistryError> {
        let gauge = |name: &str, help: &str| registry.gauge_vec(name, help, VALIDATOR);
        let counter = |name: &str, help: &str| registry.counter_vec(name, help, VALIDATOR);
        Ok(Self {
            on_chain_attester_hit: counter(
                "validator_monitor_prev_epoch_on_chain_attester_hit",
                "Previous epoch votes recorded on chain.",
            )?,
            on_chain_attester_miss: counter(
                "validator_monitor_prev_epoch_on_chain_attester_miss",
                "Previous epoch votes missing on chain.",
            )?,
            on_chain_head_attester_hit: counter(
                "validator_monitor_prev_epoch_on_chain_head_attester_hit",
                "Previous epoch votes with the right head.",
            )?,
            on_chain_head_attester_miss: counter(
                "validator_monitor_prev_epoch_on_chain_head_attester_miss",
                "Previous epoch votes without the right head.",
            )?,
            on_chain_target_attester_hit: counter(
                "validator_monitor_prev_epoch_on_chain_target_attester_hit",
                "Previous epoch votes with the right target.",
            )?,
            on_chain_target_attester_miss: counter(
                "validator_monitor_prev_epoch_on_chain_target_attester_miss",
                "Previous epoch votes without the right target.",
            )?,
            on_chain_inclusion_distance: gauge(
                "validator_monitor_prev_epoch_on_chain_inclusion_distance",
                "Inclusion distance of the previous epoch vote.",
            )?,
            in_current_sync_committee: gauge(
                "validator_monitor_validator_in_current_sync_committee",
                "One if in the current sync committee.",
            )?,
            missed_blocks: counter("validator_monitor_missed_blocks_total", "Proposals missed.")?,
        })
    }
}

/// What the node saw of each watched validator in the latest settled epoch.
#[derive(Clone, Debug)]
pub(crate) struct SummaryMetrics {
    /// Single votes seen in the previous epoch.
    pub(crate) attestations: GaugeVec<1>,

    /// Earliest single vote of the previous epoch, past its slot's start.
    pub(crate) attestations_min_delay: HistogramVec<1>,

    /// Aggregates holding the validator's vote, in the previous epoch.
    pub(crate) attestation_aggregate_inclusions: GaugeVec<1>,

    /// Blocks holding the validator's vote, in the previous epoch.
    pub(crate) attestation_block_inclusions: GaugeVec<1>,

    /// Smallest inclusion distance of the validator's votes of the previous epoch.
    pub(crate) attestation_block_min_inclusion_distance: GaugeVec<1>,

    /// Blocks the validator proposed in the previous epoch.
    pub(crate) beacon_blocks: GaugeVec<1>,

    /// Earliest block of the previous epoch, past its slot's start.
    pub(crate) beacon_blocks_min_delay: HistogramVec<1>,

    /// Aggregates the validator sent in the previous epoch.
    pub(crate) aggregates: GaugeVec<1>,

    /// Earliest aggregate of the previous epoch, past its due time.
    pub(crate) aggregates_min_delay: HistogramVec<1>,

    /// Exits seen in the previous epoch.
    pub(crate) exits: GaugeVec<1>,

    /// Proposer slashings seen in the previous epoch.
    pub(crate) proposer_slashings: GaugeVec<1>,

    /// Attester slashings seen in the previous epoch.
    pub(crate) attester_slashings: GaugeVec<1>,

    /// Sync committee messages seen in the previous epoch.
    pub(crate) sync_committee_messages: GaugeVec<1>,

    /// Earliest sync committee message of the previous epoch, past its due time.
    pub(crate) sync_committee_messages_min_delay: HistogramVec<1>,

    /// Contributions holding the validator's sync signature, in the previous epoch.
    pub(crate) sync_contribution_inclusions: GaugeVec<1>,

    /// Blocks holding the validator's sync signature, in the previous epoch.
    pub(crate) sync_signature_block_inclusions: GaugeVec<1>,

    /// Contributions the validator sent in the previous epoch.
    pub(crate) sync_contributions: GaugeVec<1>,

    /// Earliest contribution of the previous epoch, past its due time.
    pub(crate) sync_contribution_min_delay: HistogramVec<1>,
}

impl SummaryMetrics {
    /// Registers the group in a registry.
    fn register(registry: &Registry, buckets: &Buckets) -> Result<Self, RegistryError> {
        let gauge = |name: &str, help: &str| registry.gauge_vec(name, help, VALIDATOR);
        let histogram =
            |name: &str, help: &str| registry.histogram_vec(name, help, VALIDATOR, buckets.clone());
        Ok(Self {
            attestations: gauge(
                "validator_monitor_prev_epoch_attestations_total",
                "Single votes seen in the previous epoch.",
            )?,
            attestations_min_delay: histogram(
                "validator_monitor_prev_epoch_attestations_min_delay_seconds",
                "Earliest single vote of the previous epoch past its slot start.",
            )?,
            attestation_aggregate_inclusions: gauge(
                "validator_monitor_prev_epoch_attestation_aggregate_inclusions",
                "Aggregates holding the vote, in the previous epoch.",
            )?,
            attestation_block_inclusions: gauge(
                "validator_monitor_prev_epoch_attestation_block_inclusions",
                "Blocks holding the vote, in the previous epoch.",
            )?,
            attestation_block_min_inclusion_distance: gauge(
                "validator_monitor_prev_epoch_attestation_block_min_inclusion_distance",
                "Smallest inclusion distance in the previous epoch.",
            )?,
            beacon_blocks: gauge(
                "validator_monitor_prev_epoch_beacon_blocks_total",
                "Blocks proposed in the previous epoch.",
            )?,
            beacon_blocks_min_delay: histogram(
                "validator_monitor_prev_epoch_beacon_blocks_min_delay_seconds",
                "Earliest block of the previous epoch past its slot start.",
            )?,
            aggregates: gauge(
                "validator_monitor_prev_epoch_aggregates_total",
                "Aggregates sent in the previous epoch.",
            )?,
            aggregates_min_delay: histogram(
                "validator_monitor_prev_epoch_aggregates_min_delay_seconds",
                "Earliest aggregate of the previous epoch past its due time.",
            )?,
            exits: gauge(
                "validator_monitor_prev_epoch_exits_total",
                "Exits seen in the previous epoch.",
            )?,
            proposer_slashings: gauge(
                "validator_monitor_prev_epoch_proposer_slashings_total",
                "Proposer slashings seen in the previous epoch.",
            )?,
            attester_slashings: gauge(
                "validator_monitor_prev_epoch_attester_slashings_total",
                "Attester slashings seen in the previous epoch.",
            )?,
            sync_committee_messages: gauge(
                "validator_monitor_prev_epoch_sync_committee_messages_total",
                "Sync committee messages seen in the previous epoch.",
            )?,
            sync_committee_messages_min_delay: histogram(
                "validator_monitor_prev_epoch_sync_committee_messages_min_delay_seconds",
                "Earliest sync message of the previous epoch past its due time.",
            )?,
            sync_contribution_inclusions: gauge(
                "validator_monitor_prev_epoch_sync_contribution_inclusions",
                "Contributions holding the sync signature, in the previous epoch.",
            )?,
            sync_signature_block_inclusions: gauge(
                "validator_monitor_prev_epoch_sync_signature_block_inclusions",
                "Blocks holding the sync signature, in the previous epoch.",
            )?,
            sync_contributions: gauge(
                "validator_monitor_prev_epoch_sync_contributions_total",
                "Contributions sent in the previous epoch.",
            )?,
            sync_contribution_min_delay: histogram(
                "validator_monitor_prev_epoch_sync_contribution_min_delay_seconds",
                "Earliest contribution of the previous epoch past its due time.",
            )?,
        })
    }
}

/// Each message of a watched validator, by where the node saw it.
#[derive(Clone, Debug)]
pub(crate) struct MessageMetrics {
    /// Single votes seen.
    pub(crate) unaggregated_attestation: CounterVec<2>,

    /// Delay of single votes past their slot's start.
    pub(crate) unaggregated_attestation_delay: HistogramVec<2>,

    /// Aggregates the validator sent.
    pub(crate) aggregated_attestation: CounterVec<2>,

    /// Delay of the validator's aggregates past their due time.
    pub(crate) aggregated_attestation_delay: HistogramVec<2>,

    /// Aggregates holding the validator's vote.
    pub(crate) attestation_in_aggregate: CounterVec<2>,

    /// Delay of the aggregates holding the validator's vote.
    pub(crate) attestation_in_aggregate_delay: HistogramVec<2>,

    /// Blocks holding the validator's vote.
    pub(crate) attestation_in_block: CounterVec<2>,

    /// Slots of inclusion beyond the minimum, for the validator's latest included vote.
    pub(crate) attestation_in_block_delay_slots: GaugeVec<2>,

    /// Sync committee messages seen.
    pub(crate) sync_committee_messages: CounterVec<2>,

    /// Delay of sync committee messages past their due time.
    pub(crate) sync_committee_messages_delay: HistogramVec<2>,

    /// Contributions the validator sent.
    pub(crate) sync_contributions: CounterVec<2>,

    /// Delay of the validator's contributions past their due time.
    pub(crate) sync_contributions_delay: HistogramVec<2>,

    /// Contributions holding the validator's sync signature.
    pub(crate) sync_committee_message_in_contribution: CounterVec<2>,

    /// Blocks holding the validator's sync signature.
    pub(crate) sync_committee_message_in_block: CounterVec<2>,

    /// Blocks the validator proposed.
    pub(crate) beacon_block: CounterVec<2>,

    /// Delay of the validator's blocks past their slot's start.
    pub(crate) beacon_block_delay: HistogramVec<2>,

    /// Voluntary exits of the validator.
    pub(crate) exit: CounterVec<2>,

    /// Proposer slashings of the validator.
    pub(crate) proposer_slashing: CounterVec<2>,

    /// Attester slashings of the validator.
    pub(crate) attester_slashing: CounterVec<2>,
}

impl MessageMetrics {
    /// Registers the group in a registry.
    fn register(registry: &Registry, buckets: &Buckets) -> Result<Self, RegistryError> {
        let source_counter =
            |name: &str, help: &str| registry.counter_vec(name, help, SOURCE_VALIDATOR);
        let source_histogram = |name: &str, help: &str| {
            registry.histogram_vec(name, help, SOURCE_VALIDATOR, buckets.clone())
        };
        Ok(Self {
            unaggregated_attestation: source_counter(
                "validator_monitor_unaggregated_attestation_total",
                "Single votes seen.",
            )?,
            unaggregated_attestation_delay: source_histogram(
                "validator_monitor_unaggregated_attestation_delay_seconds",
                "Delay of single votes past their slot start.",
            )?,
            aggregated_attestation: source_counter(
                "validator_monitor_aggregated_attestation_total",
                "Aggregates sent.",
            )?,
            aggregated_attestation_delay: source_histogram(
                "validator_monitor_aggregated_attestation_delay_seconds",
                "Delay of aggregates past their due time.",
            )?,
            attestation_in_aggregate: source_counter(
                "validator_monitor_attestation_in_aggregate_total",
                "Aggregates holding the vote.",
            )?,
            attestation_in_aggregate_delay: source_histogram(
                "validator_monitor_attestation_in_aggregate_delay_seconds",
                "Delay of the aggregates holding the vote.",
            )?,
            attestation_in_block: source_counter(
                "validator_monitor_attestation_in_block_total",
                "Blocks holding the vote.",
            )?,
            attestation_in_block_delay_slots: registry.gauge_vec(
                "validator_monitor_attestation_in_block_delay_slots",
                "Slots of inclusion beyond the minimum.",
                SOURCE_VALIDATOR,
            )?,
            sync_committee_messages: source_counter(
                "validator_monitor_sync_committee_messages_total",
                "Sync committee messages seen.",
            )?,
            sync_committee_messages_delay: source_histogram(
                "validator_monitor_sync_committee_messages_delay_seconds",
                "Delay of sync committee messages past their due time.",
            )?,
            sync_contributions: source_counter(
                "validator_monitor_sync_contributions_total",
                "Contributions sent.",
            )?,
            sync_contributions_delay: source_histogram(
                "validator_monitor_sync_contributions_delay_seconds",
                "Delay of contributions past their due time.",
            )?,
            sync_committee_message_in_contribution: source_counter(
                "validator_monitor_sync_committee_message_in_contribution_total",
                "Contributions holding the sync signature.",
            )?,
            sync_committee_message_in_block: source_counter(
                "validator_monitor_sync_committee_message_in_block_total",
                "Blocks holding the sync signature.",
            )?,
            beacon_block: source_counter(
                "validator_monitor_beacon_block_total",
                "Blocks proposed.",
            )?,
            beacon_block_delay: source_histogram(
                "validator_monitor_beacon_block_delay_seconds",
                "Delay of blocks past their slot start.",
            )?,
            exit: source_counter("validator_monitor_exit_total", "Voluntary exits.")?,
            proposer_slashing: source_counter(
                "validator_monitor_proposer_slashing_total",
                "Proposer slashings.",
            )?,
            attester_slashing: source_counter(
                "validator_monitor_attester_slashing_total",
                "Attester slashings.",
            )?,
        })
    }
}
