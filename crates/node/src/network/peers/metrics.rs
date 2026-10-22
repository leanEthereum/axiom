//! The Prometheus metrics of peer management.
//!
//! Every name is specific to this client; the shared peer count lives with the node's metrics.

use axiom_telemetry::{CounterVec, Gauge, GaugeVec, Registry, RegistryError};

use super::{Census, PeerAction, Subnet};

/// Peer management metrics, registered together.
#[derive(Clone, Debug)]
pub(crate) struct PeerMetrics {
    /// Connected peers by direction.
    pub(crate) by_direction: GaugeVec<1>,
    /// Connected peers by transport.
    pub(crate) by_transport: GaugeVec<1>,
    /// Peers banned now.
    pub(crate) banned: Gauge,
    /// Disconnections this node asked for, by goodbye reason.
    pub(crate) goodbyes: CounterVec<1>,
    /// Faults recorded against peers, by severity.
    pub(crate) faults: CounterVec<1>,
    /// Peers serving each subnet the node needs.
    pub(crate) subnet_peers: GaugeVec<2>,
    /// Dials started, by transport.
    pub(crate) dials: CounterVec<1>,
}

impl PeerMetrics {
    /// Registers every peer metric in a registry.
    ///
    /// # Errors
    ///
    /// Fails when a name is already taken.
    pub(crate) fn register(registry: &Registry) -> Result<Self, RegistryError> {
        Ok(Self {
            by_direction: registry.gauge_vec(
                "network_peers_by_direction",
                "Connected peers by who dialed.",
                ["direction"],
            )?,
            by_transport: registry.gauge_vec(
                "network_peers_by_transport",
                "Connected peers by transport.",
                ["transport"],
            )?,
            banned: registry.gauge("network_peers_banned", "Peers banned now.")?,
            goodbyes: registry.counter_vec(
                "network_goodbyes_total",
                "Disconnections this node asked for, by goodbye reason.",
                ["reason"],
            )?,
            faults: registry.counter_vec(
                "network_peer_faults_total",
                "Faults recorded against peers, by severity.",
                ["severity"],
            )?,
            subnet_peers: registry.gauge_vec(
                "network_subnet_peers",
                "Peers serving each subnet the node subscribes to.",
                ["kind", "subnet"],
            )?,
            dials: registry.counter_vec(
                "network_dials_total",
                "Dials started, by transport.",
                ["transport"],
            )?,
        })
    }

    /// Sets the gauges from a census.
    pub(crate) fn observe(&self, census: Census) {
        self.by_direction
            .with_label_values(["inbound"])
            .set_count(census.inbound as u64);
        self.by_direction
            .with_label_values(["outbound"])
            .set_count(census.outbound as u64);
        self.by_transport
            .with_label_values(["quic"])
            .set_count(census.quic as u64);
        self.by_transport
            .with_label_values(["tcp"])
            .set_count(census.tcp as u64);
        self.banned.set_count(census.banned as u64);
    }

    /// Sets the peer count of a subnet.
    pub(crate) fn observe_subnet(&self, subnet: Subnet, peers: usize) {
        self.subnet_peers
            .with_label_values([subnet.kind_label(), &subnet.index().to_string()])
            .set_count(peers as u64);
    }

    /// Counts a fault.
    pub(crate) fn fault(&self, action: PeerAction) {
        self.faults.with_label_values([action.label()]).inc();
    }

    /// Counts a goodbye by its reason code.
    pub(crate) fn goodbye(&self, reason: u64) {
        self.goodbyes.with_label_values([&reason.to_string()]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_family() {
        let registry = Registry::new();
        let metrics = PeerMetrics::register(&registry).unwrap();
        metrics.observe(Census {
            inbound: 3,
            outbound: 2,
            quic: 4,
            tcp: 1,
            banned: 1,
        });
        metrics.observe_subnet(Subnet::Attestation(5), 2);
        metrics.fault(PeerAction::MidTolerance);
        metrics.goodbye(129);
        metrics.dials.with_label_values(["quic"]).inc();
        let text = registry.render();
        for line in [
            "network_peers_by_direction{direction=\"inbound\"} 3",
            "network_peers_by_transport{transport=\"quic\"} 4",
            "network_peers_banned 1",
            "network_subnet_peers{kind=\"attestation\",subnet=\"5\"} 2",
            "network_peer_faults_total{severity=\"mid_tolerance\"} 1",
            "network_goodbyes_total{reason=\"129\"} 1",
            "network_dials_total{transport=\"quic\"} 1",
        ] {
            assert!(text.contains(line), "missing {line} in {text}");
        }
        // A second registration in the same registry fails on the first name.
        assert!(PeerMetrics::register(&registry).is_err());
    }
}
