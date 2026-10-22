//! The metrics a beacon node exports.
//!
//! Names marked standard follow the cross-client beacon metrics specification.
//! Source: <https://github.com/ethereum/beacon-metrics>.
//! The rest are specific to this client.

use crate::metrics::{
    Buckets, Counter, CounterVec, Gauge, Histogram, HistogramVec, Registry, RegistryError,
};

/// Bucket count of every latency histogram.
///
/// Twelve doublings span three orders of magnitude, from a cache hit to a stall.
const LATENCY_BUCKETS: usize = 12;

/// Every metric the node updates, registered together.
#[derive(Clone, Debug)]
pub struct NodeMetrics {
    /// Standard: slot of the head block.
    pub head_slot: Gauge,

    /// Standard: the finalized checkpoint epoch.
    pub finalized_epoch: Gauge,

    /// Standard: the current justified checkpoint epoch.
    pub current_justified_epoch: Gauge,

    /// Standard: the previous justified checkpoint epoch.
    pub previous_justified_epoch: Gauge,

    /// Standard: active validators in the current epoch.
    pub current_active_validators: Gauge,

    /// Standard: head changes that left the old head off the new chain.
    pub reorgs: Counter,

    /// Standard: the deposit index of the head state.
    ///
    /// The specification declares it a gauge despite its counter-style name.
    pub processed_deposits: Gauge,

    /// Standard: connected libp2p peers.
    pub peers: Gauge,

    /// The slot the wall clock is in.
    pub clock_slot: Gauge,

    /// Seconds to import a block, from receipt to fork choice.
    pub block_import_seconds: Histogram,

    /// Seconds to recompute the head.
    pub fork_choice_seconds: Histogram,

    /// Gossip messages by topic and validation outcome.
    pub gossip_messages: CounterVec<2>,

    /// Seconds per engine API request, by method.
    pub engine_request_seconds: HistogramVec<1>,

    /// Bytes the store has written.
    pub store_bytes_written: Counter,

    /// Lookups started for blocks gossip named and the chain lacked.
    pub sync_lookups_created: Counter,

    /// Lookups whose blocks were all imported.
    pub sync_lookups_completed: Counter,

    /// Lookups given up, by reason.
    pub sync_lookups_dropped: CounterVec<1>,
}

impl NodeMetrics {
    /// Registers every node metric in a registry.
    ///
    /// # Errors
    ///
    /// Fails when a name is already taken in the registry.
    pub fn register(registry: &Registry) -> Result<Self, RegistryError> {
        // Block import and state transition run from milliseconds to seconds.
        //
        //     5 ms, 10 ms, ..., 10.24 s
        let slow = Self::latency_buckets(0.005);
        // Fork choice works in memory, so its scale starts ten times lower.
        //
        //     0.5 ms, 1 ms, ..., 1.024 s
        let fast = Self::latency_buckets(0.0005);

        Ok(Self {
            // Standard set: every dashboard built on the shared specification reads these.
            head_slot: registry.gauge("beacon_head_slot", "Slot of the head block.")?,
            finalized_epoch: registry.gauge(
                "beacon_finalized_epoch",
                "Epoch of the finalized checkpoint.",
            )?,
            current_justified_epoch: registry.gauge(
                "beacon_current_justified_epoch",
                "Epoch of the current justified checkpoint.",
            )?,
            previous_justified_epoch: registry.gauge(
                "beacon_previous_justified_epoch",
                "Epoch of the previous justified checkpoint.",
            )?,
            current_active_validators: registry.gauge(
                "beacon_current_active_validators",
                "Active validators in the current epoch.",
            )?,
            reorgs: registry.counter("beacon_reorgs_total", "Chain reorganizations seen.")?,
            processed_deposits: registry.gauge(
                "beacon_processed_deposits_total",
                "Deposits processed by the head state.",
            )?,
            peers: registry.gauge("libp2p_peers", "Connected libp2p peers.")?,

            // Client set: timings and throughput specific to this node.
            clock_slot: registry.gauge("beacon_clock_slot", "Slot of the wall clock.")?,
            block_import_seconds: registry.histogram(
                "beacon_block_import_seconds",
                "Time to import a block.",
                slow.clone(),
            )?,
            fork_choice_seconds: registry.histogram(
                "beacon_fork_choice_seconds",
                "Time to recompute the head.",
                fast,
            )?,
            gossip_messages: registry.counter_vec(
                "gossip_messages_total",
                "Gossip messages by topic and validation outcome.",
                ["topic", "outcome"],
            )?,
            engine_request_seconds: registry.histogram_vec(
                "engine_requests_seconds",
                "Time per engine API request.",
                ["method"],
                slow,
            )?,
            store_bytes_written: registry
                .counter("store_bytes_written_total", "Bytes written to the store.")?,
            sync_lookups_created: registry.counter(
                "sync_lookups_created_total",
                "Block lookups started for unknown roots.",
            )?,
            sync_lookups_completed: registry.counter(
                "sync_lookups_completed_total",
                "Block lookups whose blocks were imported.",
            )?,
            sync_lookups_dropped: registry.counter_vec(
                "sync_lookups_dropped_total",
                "Block lookups given up, by reason.",
                ["reason"],
            )?,
        })
    }

    /// Metrics in a registry of their own, which nothing exports.
    ///
    /// Components that record metrics use this when the node does not export them, as in tests.
    #[must_use]
    pub fn detached() -> Self {
        // Invariant: a fresh registry holds no names, and the set's own names are distinct.
        // Registration can only fail on a taken name, so it cannot fail here.
        Self::register(&Registry::new()).expect("a fresh registry takes every node metric")
    }

    /// Twelve doubling bucket bounds from a starting latency in seconds.
    fn latency_buckets(start: f64) -> Buckets {
        // Invariant: the start is a positive finite literal, the factor is 2, and the count is 12.
        // The largest bound is start times 2^11, far below the float range, so the series is valid.
        Buckets::exponential(start, 2.0, LATENCY_BUCKETS).expect("valid doubling series")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_once_per_registry() {
        let registry = Registry::new();

        // The first registration takes every name.
        let metrics = NodeMetrics::register(&registry).expect("fresh registry");
        metrics.head_slot.set(96);

        // A second registration stops at its first name, already taken.
        assert_eq!(
            NodeMetrics::register(&registry).map(|_| ()),
            Err(RegistryError::DuplicateMetric(
                "beacon_head_slot".to_owned()
            ))
        );

        // The head slot line appears with its value.
        assert!(registry.render().contains("\nbeacon_head_slot 96\n"));
    }

    #[test]
    fn detached_metrics_record_without_a_shared_registry() {
        // Two detached sets never clash, and each keeps its own values.
        let first = NodeMetrics::detached();
        let second = NodeMetrics::detached();

        first.reorgs.inc();

        assert_eq!(first.reorgs.get(), 1);
        assert_eq!(second.reorgs.get(), 0);
    }
}
