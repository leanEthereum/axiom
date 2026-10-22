//! The client stats push: process, host, and beacon node figures sent to a remote collector.
//!
//! The record format is the one beaconcha.in's client stats collector reads, version 1.
//! See the client stats specification on the beaconcha.in documentation site.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axiom_http::{Client, ClientConfig, Endpoint, HttpError, Method, Request, StatusCode};
use axiom_json::Json;
use axiom_telemetry::{NodeMetrics, ProcessUsage, SystemUsage};
use axiom_types::Preset;
use tokio::time;
use tracing::{debug, info, warn};

use crate::{ChainHandle, Clock, chain::SYNCING_DISTANCE};

/// The record format's version.
const FORMAT_VERSION: u64 = 1;

/// The client name records carry.
const CLIENT_NAME: &str = "axiom";

/// Time between pushes when the operator names none: one minute.
pub const DEFAULT_PUSH_PERIOD: Duration = Duration::from_secs(60);

/// Time before the first push, so the node has started its services.
const FIRST_PUSH_DELAY: Duration = Duration::from_secs(25);

/// How long a push may take before it is abandoned.
const PUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Where and how often the node pushes its stats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientStatsSettings {
    /// The collector's URL, its key in the query, such as `http://host/api/v1/client/metrics?apikey=K`.
    pub endpoint: String,
    /// Time between pushes.
    pub period: Duration,
}

/// The client stats pusher: one beacon node record and one system record, every period.
///
/// A failed push is logged and the next one tries again; the node never depends on the collector.
#[derive(Debug)]
pub(crate) struct ClientStats<P: Preset> {
    /// The chain thread, for the head.
    chain: ChainHandle<P>,
    /// The wall clock, for timestamps.
    clock: Arc<dyn Clock>,
    /// The node's metrics, for the peer count.
    metrics: NodeMetrics,
    /// The database directory, whose size is reported; none reports zero.
    database: Option<PathBuf>,
    /// The collector's client.
    client: Client,
    /// The collector's path and query.
    target: String,
    /// Time between pushes.
    period: Duration,
}

impl<P: Preset> ClientStats<P> {
    /// A pusher to a collector.
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is not a plain http URL.
    pub(crate) fn new(
        settings: &ClientStatsSettings,
        chain: ChainHandle<P>,
        clock: Arc<dyn Clock>,
        metrics: NodeMetrics,
        database: Option<&Path>,
    ) -> Result<Self, HttpError> {
        let endpoint = Endpoint::parse(&settings.endpoint)?;
        let target = endpoint.path().to_owned();
        let config = ClientConfig {
            request_timeout: PUSH_TIMEOUT,
            ..ClientConfig::default()
        };
        Ok(Self {
            chain,
            clock,
            metrics,
            database: database.map(Path::to_path_buf),
            client: Client::new(endpoint, config),
            target,
            period: settings.period,
        })
    }

    /// Pushes every period until aborted.
    pub(crate) async fn run(self) {
        info!(period_s = self.period.as_secs(), "pushing client stats");
        time::sleep(FIRST_PUSH_DELAY).await;
        loop {
            match self.push().await {
                Ok(()) => debug!("client stats pushed"),
                Err(error) => warn!(%error, "client stats push failed"),
            }
            time::sleep(self.period).await;
        }
    }

    /// Sends the current records.
    async fn push(&self) -> Result<(), String> {
        let body = self.records().await.to_string().into_bytes();
        let request = Request::new(Method::Post, &self.target).with_body("application/json", body);
        let response = self
            .client
            .send(&request)
            .await
            .map_err(|error| error.to_string())?;
        if response.status == StatusCode::OK {
            Ok(())
        } else {
            Err(format!(
                "collector answered {}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            ))
        }
    }

    /// The beacon node record and the system record.
    pub(crate) async fn records(&self) -> Json {
        let now = self.clock.now_ms();
        let (head_slot, synced) = self
            .chain
            .run(|chain| {
                let head = chain.head().slot;
                let distance = chain.store().current_slot().0.saturating_sub(head.0);
                (head.0, distance < SYNCING_DISTANCE)
            })
            .await
            .unwrap_or((0, false));
        let process = ProcessUsage::sample();
        let peers = u64::try_from(self.metrics.peers.get()).unwrap_or(0);
        let disk = self.database.as_deref().map_or(0, Self::size_of);
        let beacon = Json::from([
            ("version", Json::from(FORMAT_VERSION)),
            ("timestamp", Json::from(now)),
            ("process", Json::from("beaconnode")),
            ("cpu_process_seconds_total", Json::from(process.cpu_seconds)),
            ("memory_process_bytes", Json::from(process.resident_bytes)),
            ("client_name", Json::from(CLIENT_NAME)),
            ("client_version", Json::from(env!("CARGO_PKG_VERSION"))),
            ("client_build", Json::from(0_u64)),
            // Eth1 following is gone from every client; the fields stay for the format.
            ("sync_eth1_fallback_configured", Json::from(false)),
            ("sync_eth1_fallback_connected", Json::from(false)),
            ("sync_eth1_connected", Json::from(false)),
            ("disk_beaconchain_bytes_total", Json::from(disk)),
            ("network_peers_connected", Json::from(peers)),
            ("network_libp2p_bytes_total_transmit", Json::from(0_u64)),
            ("network_libp2p_bytes_total_receive", Json::from(0_u64)),
            ("sync_beacon_head_slot", Json::from(head_slot)),
            ("sync_eth2_synced", Json::from(synced)),
        ]);
        let host = SystemUsage::sample();
        let system = Json::from([
            ("version", Json::from(FORMAT_VERSION)),
            ("timestamp", Json::from(now)),
            ("process", Json::from("system")),
            ("cpu_cores", Json::from(host.cpu_cores)),
            ("cpu_threads", Json::from(host.cpu_threads)),
            (
                "cpu_node_system_seconds_total",
                Json::from(host.cpu_total_seconds),
            ),
            (
                "cpu_node_user_seconds_total",
                Json::from(host.cpu_user_seconds),
            ),
            (
                "cpu_node_iowait_seconds_total",
                Json::from(host.cpu_iowait_seconds),
            ),
            (
                "cpu_node_idle_seconds_total",
                Json::from(host.cpu_idle_seconds),
            ),
            (
                "memory_node_bytes_total",
                Json::from(host.memory_total_bytes),
            ),
            ("memory_node_bytes_free", Json::from(host.memory_free_bytes)),
            (
                "memory_node_bytes_cached",
                Json::from(host.memory_cached_bytes),
            ),
            (
                "memory_node_bytes_buffers",
                Json::from(host.memory_buffers_bytes),
            ),
            // File system sizes need a system call the standard library does not offer.
            ("disk_node_bytes_total", Json::from(0_u64)),
            ("disk_node_bytes_free", Json::from(0_u64)),
            ("disk_node_io_seconds", Json::from(0_u64)),
            ("disk_node_reads_total", Json::from(host.disk_reads)),
            ("disk_node_writes_total", Json::from(host.disk_writes)),
            (
                "network_node_bytes_total_receive",
                Json::from(host.network_received_bytes),
            ),
            (
                "network_node_bytes_total_transmit",
                Json::from(host.network_transmitted_bytes),
            ),
            (
                "misc_node_boot_ts_seconds",
                Json::from(host.boot_time_seconds),
            ),
            ("misc_os", Json::from(Self::os())),
        ]);
        Json::Array(vec![beacon, system])
    }

    /// The bytes of the files under a directory, recursively.
    fn size_of(directory: &Path) -> u64 {
        let Ok(entries) = fs::read_dir(directory) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => Self::size_of(&entry.path()),
                Ok(metadata) => metadata.len(),
                Err(_) => 0,
            })
            .sum()
    }

    /// The operating system, in the format's three letters.
    fn os() -> &'static str {
        match env::consts::OS {
            "linux" => "lin",
            "macos" => "mac",
            "windows" => "win",
            _ => "unk",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axiom_http::{Response, Router, Server, ServerConfig};
    use axiom_types::{ChainConfig, Minimal, combined, phase0};
    use tokio::{runtime::Builder, sync::oneshot, task};

    use super::*;
    use crate::{Chain, ChainDatabase, ManualClock};

    #[test]
    fn a_push_sends_a_beacon_node_and_a_system_record() {
        // Fixture state: a collector that keeps each body, and a chain at genesis.
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let config = ChainConfig::minimal();
        let database = ChainDatabase::in_memory(config.clone()).unwrap();
        let genesis = combined::BeaconState::Phase0(phase0::BeaconState::<Minimal>::default());
        let chain = Chain::from_genesis(config, genesis, database).unwrap();
        let (chain, _thread) = ChainHandle::spawn(chain).unwrap();
        runtime.block_on(async {
            let bodies = Arc::new(Mutex::new(Vec::new()));
            let kept = Arc::clone(&bodies);
            let router =
                Router::new().route(Method::Post, "/api/v1/client/metrics", move |request| {
                    kept.lock().unwrap().push(request.body);
                    async { Response::new(StatusCode::OK) }
                });
            let server = Server::bind("127.0.0.1:0", router, ServerConfig::default())
                .await
                .unwrap();
            let address = server.local_addr().unwrap();
            let (stop, stopped) = oneshot::channel::<()>();
            let serving = task::spawn(server.serve(async {
                let _stopped = stopped.await;
            }));
            let settings = ClientStatsSettings {
                endpoint: format!("http://{address}/api/v1/client/metrics?apikey=secret"),
                period: DEFAULT_PUSH_PERIOD,
            };
            let stats = ClientStats::new(
                &settings,
                chain,
                Arc::new(ManualClock::at(1_700_000_000_000)),
                NodeMetrics::detached(),
                None,
            )
            .unwrap();

            stats.push().await.unwrap();

            // One body: two records, the beacon node's then the system's, both version 1.
            let bodies = bodies.lock().unwrap().clone();
            assert_eq!(bodies.len(), 1);
            let records = Json::parse(&bodies[0]).unwrap();
            let records = records.as_array().unwrap();
            let field = |index: usize, name: &str| records[index].get(name).cloned();
            assert_eq!(records.len(), 2);
            assert_eq!(field(0, "process"), Some(Json::from("beaconnode")));
            assert_eq!(field(1, "process"), Some(Json::from("system")));
            assert_eq!(field(1, "version"), Some(Json::from(1_u64)));
            assert_eq!(
                field(0, "timestamp"),
                Some(Json::from(1_700_000_000_000_u64))
            );
            assert_eq!(field(0, "client_name"), Some(Json::from("axiom")));
            assert_eq!(field(0, "sync_beacon_head_slot"), Some(Json::from(0_u64)));
            assert_eq!(field(0, "network_peers_connected"), Some(Json::from(0_u64)));
            let _stopping = stop.send(());
            let _served = serving.await;
        });
    }
}
