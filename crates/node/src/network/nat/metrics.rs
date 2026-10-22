//! Prometheus metrics of port mapping and external address discovery.

use axiom_telemetry::{CounterVec, Gauge, GaugeVec, Registry, RegistryError};

use super::MappingProtocol;

/// Every port mapping and external address metric, registered together.
#[derive(Clone, Debug)]
pub(crate) struct NatMetrics {
    /// One while a protocol keeps mappings alive, zero otherwise.
    mapping_active: GaugeVec<1>,
    /// One once the node knows its external address.
    external_address_known: Gauge,
    /// Distinct voter networks behind the last confirmed address.
    address_votes: Gauge,
    /// Mappings renewed, by protocol.
    renewals: CounterVec<1>,
    /// Failed mapping attempts and renewals, by protocol.
    failures: CounterVec<1>,
}

impl NatMetrics {
    /// Registers the metrics in a registry.
    ///
    /// # Errors
    ///
    /// Fails when a name is already taken in the registry.
    pub(crate) fn register(registry: &Registry) -> Result<Self, RegistryError> {
        Ok(Self {
            mapping_active: registry.gauge_vec(
                "nat_port_mapping_active",
                "Whether a protocol keeps port mappings alive.",
                ["protocol"],
            )?,
            external_address_known: registry.gauge(
                "nat_external_address_known",
                "Whether the node knows its external address.",
            )?,
            address_votes: registry.gauge(
                "nat_external_address_votes",
                "Distinct peer networks behind the confirmed external address.",
            )?,
            renewals: registry.counter_vec(
                "nat_port_mapping_renewals_total",
                "Port mappings renewed.",
                ["protocol"],
            )?,
            failures: registry.counter_vec(
                "nat_port_mapping_failures_total",
                "Failed port mapping attempts and renewals.",
                ["protocol"],
            )?,
        })
    }

    /// Metrics in a registry of their own, which nothing exports.
    pub(crate) fn detached() -> Self {
        // Invariant: a fresh registry holds no names, and this set's names are distinct.
        // Registration can only fail on a taken name, so it cannot fail here.
        Self::register(&Registry::new()).expect("a fresh registry takes every name")
    }

    /// Marks whether a protocol keeps mappings alive.
    pub(crate) fn set_active(&self, protocol: MappingProtocol, active: bool) {
        self.mapping_active
            .with_label_values([protocol.label()])
            .set(i64::from(active));
    }

    /// Marks whether the external address is known.
    pub(crate) fn set_address_known(&self, known: bool) {
        self.external_address_known.set(i64::from(known));
    }

    /// Records the networks behind a newly confirmed address.
    pub(crate) fn set_address_votes(&self, votes: usize) {
        self.address_votes.set_count(votes as u64);
    }

    /// Counts a renewed mapping.
    pub(crate) fn renewed(&self, protocol: MappingProtocol) {
        self.renewals.with_label_values([protocol.label()]).inc();
    }

    /// Counts a failed attempt.
    pub(crate) fn failed(&self, protocol: MappingProtocol) {
        self.failures.with_label_values([protocol.label()]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_under_their_names() {
        // One NAT-PMP mapping alive, one UPnP failure, a known address behind 12 networks.
        let registry = Registry::new();
        let metrics = NatMetrics::register(&registry).expect("names are free");
        metrics.set_active(MappingProtocol::NatPmp, true);
        metrics.renewed(MappingProtocol::NatPmp);
        metrics.failed(MappingProtocol::Upnp);
        metrics.set_address_known(true);
        metrics.set_address_votes(12);
        let text = registry.render();
        for line in [
            "nat_port_mapping_active{protocol=\"nat_pmp\"} 1",
            "nat_port_mapping_renewals_total{protocol=\"nat_pmp\"} 1",
            "nat_port_mapping_failures_total{protocol=\"upnp\"} 1",
            "nat_external_address_known 1",
            "nat_external_address_votes 12",
        ] {
            assert!(text.lines().any(|rendered| rendered == line), "{line}");
        }
        // A second registration in the same registry is refused.
        assert!(NatMetrics::register(&registry).is_err());
    }
}
