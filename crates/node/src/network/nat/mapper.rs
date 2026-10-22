//! The task that keeps the node's port mappings alive, and the handle that stops it.

use std::{fs, net::SocketAddr, time::Duration};

use tokio::{
    sync::{oneshot, watch},
    task, time,
};
use tracing::{info, warn};

use super::{
    ListenPorts, Listener, MappedEndpoint, NatMetrics,
    control::PORT_CONTROL_PORT,
    route::RouteTable,
    session::{GatewayTargets, Session},
    ssdp::SSDP_GROUP,
};
use crate::race::Either;

/// The kernel's IPv4 routing table.
const ROUTE_TABLE: &str = "/proc/net/route";

/// How long SSDP answers are collected: the advertised wait of 2 s, plus a margin.
const SSDP_WAIT: Duration = Duration::from_secs(3);

/// How often the task acts on the gateway, at most.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timing {
    /// How long the task waits after every protocol failed, before trying again.
    pub(crate) retry_after: Duration,
    /// The shortest wait between renewals, whatever lifetime the gateway grants.
    pub(crate) min_renewal: Duration,
}

impl Timing {
    /// The schedule outside tests.
    ///
    /// RFC 6887 section 7.4 suggests 30 minutes after a lasting error; ten keeps a fixed network quick.
    /// RFC 6887 section 15 sets a minimum lifetime of 120 s, renewed at half: 60 s.
    const DEFAULT: Self = Self {
        retry_after: Duration::from_secs(600),
        min_renewal: Duration::from_secs(60),
    };
}

/// A running port mapper: the latest endpoint it reports, and the way to stop it.
///
/// Dropping the handle stops the task too, which then deletes its mappings.
#[derive(Debug)]
pub(crate) struct PortMapper {
    /// The endpoint the gateway reports, or nothing while no mapping holds.
    reports: watch::Receiver<Option<MappedEndpoint>>,
    /// Dropped with the handle, which tells the task to release its mappings and stop.
    _stop: oneshot::Sender<()>,
}

impl PortMapper {
    /// Starts mapping the listeners on the default gateway.
    pub(crate) fn spawn(ports: ListenPorts, metrics: NatMetrics) -> Self {
        // Effects: the routing table is read once, at start.
        let gateway = fs::read_to_string(ROUTE_TABLE)
            .ok()
            .and_then(|text| RouteTable(&text).default_gateway());
        if gateway.is_none() {
            warn!("no IPv4 default gateway; port mapping tries UPnP only");
        }
        let targets = GatewayTargets {
            port_control: gateway.map(|ip| SocketAddr::from((ip, PORT_CONTROL_PORT))),
            ssdp: SSDP_GROUP,
            ssdp_wait: SSDP_WAIT,
        };
        Self::spawn_with(targets, ports, metrics, Timing::DEFAULT)
    }

    /// Starts mapping the listeners on given gateway servers.
    pub(crate) fn spawn_with(
        targets: GatewayTargets,
        ports: ListenPorts,
        metrics: NatMetrics,
        timing: Timing,
    ) -> Self {
        let (report, reports) = watch::channel(None);
        let (stop, stopped) = oneshot::channel();
        let mapper = MapperTask {
            targets,
            listeners: ports.listeners(),
            metrics,
            report,
            timing,
        };
        // The task is detached: it ends on its own once the handle is gone.
        task::spawn(mapper.run(stopped));
        Self {
            reports,
            _stop: stop,
        }
    }

    /// The endpoint the gateway last reported, or nothing while no mapping holds.
    pub(crate) fn latest(&self) -> Option<MappedEndpoint> {
        self.reports.borrow().clone()
    }

    /// A receiver of every report, for callers that wait on changes.
    #[cfg(test)]
    pub(crate) fn reports(&self) -> watch::Receiver<Option<MappedEndpoint>> {
        self.reports.clone()
    }
}

/// The task's state: where the gateway is, what to map, and where to report.
#[derive(Debug)]
struct MapperTask {
    /// The gateway's servers.
    targets: GatewayTargets,
    /// The local ports to forward.
    listeners: Vec<(Listener, u16)>,
    /// The metrics it updates.
    metrics: NatMetrics,
    /// Where it reports the mapped endpoint.
    report: watch::Sender<Option<MappedEndpoint>>,
    /// The pauses between attempts.
    timing: Timing,
}

impl MapperTask {
    /// Maps, renews, and on stop releases, until told to stop.
    ///
    /// No failure ends the task: the node runs on without mappings and tries again later.
    async fn run(self, mut stop: oneshot::Receiver<()>) {
        loop {
            // Phase 1: find a protocol the gateway speaks; a stop meanwhile abandons the attempt.
            let establishing = Session::establish(self.targets, &self.listeners, &self.metrics);
            let session = match Either::race(&mut stop, establishing).await {
                Either::Left(_) => return,
                Either::Right(Ok(session)) => session,
                Either::Right(Err(error)) => {
                    warn!(%error, retry_in = ?self.timing.retry_after, "port mapping failed");
                    if Self::stopped_within(&mut stop, self.timing.retry_after).await {
                        return;
                    }
                    continue;
                }
            };
            // Phase 2: keep the mappings alive until told to stop or a renewal fails.
            if self.keep(session, &mut stop).await {
                return;
            }
            if Self::stopped_within(&mut stop, self.timing.retry_after).await {
                return;
            }
        }
    }

    /// Renews a session at half its lifetime, releasing it on stop.
    ///
    /// # Returns
    ///
    /// Whether the task was told to stop; otherwise a renewal failed.
    async fn keep(&self, mut session: Session, stop: &mut oneshot::Receiver<()>) -> bool {
        let protocol = session.protocol();
        self.metrics.set_active(protocol, true);
        self.publish(Some(session.endpoint()));
        info!(%protocol, endpoint = ?session.endpoint(), "port mappings established");
        loop {
            let wait = session.renew_after().max(self.timing.min_renewal);
            if Self::stopped_within(stop, wait).await {
                session.release().await;
                self.metrics.set_active(protocol, false);
                self.publish(None);
                return true;
            }
            match session.renew().await {
                Ok(()) => {
                    self.metrics.renewed(protocol);
                    self.publish(Some(session.endpoint()));
                }
                Err(error) => {
                    warn!(%protocol, %error, "port mapping renewal failed");
                    self.metrics.failed(protocol);
                    self.metrics.set_active(protocol, false);
                    self.publish(None);
                    return false;
                }
            }
        }
    }

    /// Reports an endpoint, waking readers only when it changed.
    fn publish(&self, endpoint: Option<MappedEndpoint>) {
        self.report.send_if_modified(|current| {
            let changed = *current != endpoint;
            *current = endpoint;
            changed
        });
    }

    /// Waits for a duration, unless a stop comes first.
    ///
    /// A dropped handle counts as a stop.
    async fn stopped_within(stop: &mut oneshot::Receiver<()>, wait: Duration) -> bool {
        matches!(Either::race(stop, time::sleep(wait)).await, Either::Left(_))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::Ipv4Addr};

    use axiom_telemetry::Registry;
    use tokio::{net::UdpSocket, runtime::Builder};

    use super::*;
    use crate::network::nat::fake::{
        ControlRequest, EXTERNAL_IP, FakePortControl, FakeUpnp, UpnpCall,
    };

    /// TCP 9000, discovery on UDP 9001, QUIC on UDP 9002.
    const PORTS: ListenPorts = ListenPorts {
        tcp: Some(9000),
        quic: Some(9002),
        discovery: Some(9001),
    };

    /// Renewals as soon as half the lifetime passes; no retry within a test.
    const FAST: Timing = Timing {
        retry_after: Duration::from_secs(600),
        min_renewal: Duration::ZERO,
    };

    /// Where the mapper looks, with a short SSDP wait.
    fn targets(port_control: Option<SocketAddr>, ssdp: SocketAddr) -> GatewayTargets {
        GatewayTargets {
            port_control,
            ssdp,
            ssdp_wait: Duration::from_millis(300),
        }
    }

    /// The first endpoint the mapper reports, within ten seconds.
    async fn first_report(mapper: &PortMapper) -> MappedEndpoint {
        let mut reports = mapper.reports();
        let waited = time::timeout(Duration::from_secs(10), reports.wait_for(Option::is_some));
        let report = waited.await.expect("in time").expect("mapper alive");
        report.clone().expect("a report")
    }

    /// A UDP socket that never answers, for a search that must find nothing.
    async fn silent() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind")
    }

    /// A NAT-PMP mapping request as the fake logs it.
    fn pmp(opcode: u8, internal: u16, suggested: u16) -> ControlRequest {
        ControlRequest::PmpMap {
            opcode,
            internal,
            suggested,
            lifetime: 7200,
        }
    }

    /// A NAT-PMP deletion: zero lifetime, nothing suggested.
    fn pmp_delete(opcode: u8, internal: u16) -> ControlRequest {
        ControlRequest::PmpMap {
            opcode,
            internal,
            suggested: 0,
            lifetime: 0,
        }
    }

    #[test]
    fn nat_pmp_maps_renews_and_deletes() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: a NAT-PMP gateway granting 2 s, on port 10000 above each internal port.
            let gateway = FakePortControl::start(2, None).await;
            let search = silent().await;
            let registry = Registry::new();
            let metrics = NatMetrics::register(&registry).expect("names are free");
            let mapper = PortMapper::spawn_with(
                targets(Some(gateway.addr), search.local_addr().expect("address")),
                PORTS,
                metrics,
                FAST,
            );

            // Phase 1: the three forwardings, reported with the gateway's address.
            assert_eq!(
                first_report(&mapper).await,
                MappedEndpoint {
                    ip: EXTERNAL_IP,
                    tcp: Some(19000),
                    udp: Some(19001),
                    quic: Some(19002),
                }
            );

            // Phase 2: at half the 2 s lifetime, each renewal suggests the port granted.
            gateway.wait_for(8).await;
            assert_eq!(
                gateway.state().requests[..8],
                [
                    ControlRequest::PmpAddress,
                    pmp(2, 9000, 9000),
                    pmp(1, 9001, 9001),
                    pmp(1, 9002, 9002),
                    ControlRequest::PmpAddress,
                    pmp(2, 9000, 19000),
                    pmp(1, 9001, 19001),
                    pmp(1, 9002, 19002),
                ]
            );

            // Phase 3: dropping the handle deletes all three with a zero lifetime.
            drop(mapper);
            for _ in 0..500 {
                if gateway.state().table.is_empty() {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
            let state = gateway.state();
            assert_eq!(state.table, BTreeMap::new());
            assert_eq!(
                state.requests[state.requests.len() - 3..],
                [
                    pmp_delete(2, 9000),
                    pmp_delete(1, 9001),
                    pmp_delete(1, 9002)
                ]
            );
            drop(state);
            let text = registry.render();
            assert!(
                text.lines()
                    .any(|line| line == "nat_port_mapping_active{protocol=\"nat_pmp\"} 0")
            );
        });
    }

    #[test]
    fn nat_pmp_recreates_mappings_after_a_gateway_restart() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: a NAT-PMP-only gateway granting 2 s.
            // Mutation: it reboots right after answering request 6, in the middle of a renewal.
            let gateway = FakePortControl::start(2, Some(6)).await;
            let search = silent().await;
            let mapper = PortMapper::spawn_with(
                targets(Some(gateway.addr), search.local_addr().expect("address")),
                PORTS,
                NatMetrics::detached(),
                FAST,
            );
            assert_eq!(
                first_report(&mapper).await,
                MappedEndpoint {
                    ip: EXTERNAL_IP,
                    tcp: Some(19000),
                    udp: Some(19001),
                    quic: Some(19002),
                }
            );
            gateway.wait_for(11).await;
            let state = gateway.state();
            assert_eq!(
                state.requests[..11],
                [
                    ControlRequest::PmpAddress,
                    pmp(2, 9000, 9000),
                    pmp(1, 9001, 9001),
                    pmp(1, 9002, 9002),
                    // The renewal: the TCP mapping is answered, then the gateway reboots.
                    ControlRequest::PmpAddress,
                    pmp(2, 9000, 19000),
                    // The epoch has gone back to zero: the pass starts over.
                    pmp(1, 9001, 19001),
                    ControlRequest::PmpAddress,
                    pmp(2, 9000, 19000),
                    pmp(1, 9001, 19001),
                    pmp(1, 9002, 19002),
                ]
            );
            // The rebooted gateway holds every forwarding again, the TCP one included.
            assert_eq!(
                state.table,
                BTreeMap::from([((6, 9000), 19000), ((17, 9001), 19001), ((17, 9002), 19002)])
            );
        });
    }

    #[test]
    fn upnp_takes_over_when_no_port_control_server_answers() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: nothing listens on the NAT-PMP port; a UPnP gateway answers searches.
            let closed = silent().await.local_addr().expect("address");
            let device = FakeUpnp::start(false).await;
            let registry = Registry::new();
            let metrics = NatMetrics::register(&registry).expect("names are free");
            let mapper =
                PortMapper::spawn_with(targets(Some(closed), device.ssdp), PORTS, metrics, FAST);

            // External ports equal internal ones, on the address the gateway reports.
            assert_eq!(
                first_report(&mapper).await,
                MappedEndpoint {
                    ip: EXTERNAL_IP,
                    tcp: Some(9000),
                    udp: Some(9001),
                    quic: Some(9002),
                }
            );
            let add = |protocol: &str, port| UpnpCall::Add {
                protocol: protocol.to_owned(),
                external: port,
                internal: port,
                client: "127.0.0.1".to_owned(),
                lease: 3600,
            };
            let delete = |protocol: &str, port| UpnpCall::Delete {
                protocol: protocol.to_owned(),
                external: port,
            };

            // Dropping the handle deletes the three forwardings.
            drop(mapper);
            device.wait_for(7).await;
            let state = device.state();
            assert_eq!(
                state.calls,
                [
                    add("TCP", 9000),
                    add("UDP", 9001),
                    add("UDP", 9002),
                    UpnpCall::ExternalAddress,
                    delete("TCP", 9000),
                    delete("UDP", 9001),
                    delete("UDP", 9002),
                ]
            );
            assert_eq!(state.table, BTreeMap::new());
            drop(state);
            // The NAT-PMP attempt failed once, and counted.
            let text = registry.render();
            assert!(
                text.lines()
                    .any(|line| line == "nat_port_mapping_failures_total{protocol=\"nat_pmp\"} 1")
            );
        });
    }
}
