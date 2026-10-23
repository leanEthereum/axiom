//! What an operator chooses about a node, and how each choice opens its component.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axiom_builder_client::{CircuitBreaker, RelayClient, RelayTimeouts};
use axiom_execution::{EngineClient, JwtSecret};
use axiom_http::{Cors, Server, ServerConfig, ServerIdentity};
use axiom_p2p::{
    Multiaddr,
    eth::MessageIds,
    swarm::{self, NetworkConfig, NetworkEvents, NetworkHandle},
};
use axiom_slasher::SlasherConfig;
use axiom_ssz::{DecodeError, List, Ssz};
use axiom_store::Options;
use axiom_telemetry::{MetricsServer, NodeMetrics, Registry};
use axiom_types::{
    Bytes32, ChainConfig, ExecutionAddress, Preset, SlotClock,
    accessors::CoreState,
    combined::{BeaconState, SignedBeaconBlock},
    deneb::BlobSidecar,
};
use tokio::{
    sync::{
        mpsc::{UnboundedReceiver, unbounded_channel},
        watch,
    },
    task::{self, JoinHandle},
};
use tracing::{info, warn};

use crate::{
    BeaconApi, Chain, ChainDatabase, ChainError, ChainHandle, ChainSettings, CheckpointServer,
    ClientStatsSettings, Clock, DiscoverySettings, EventSender, ExecutionLayer, GenesisState,
    MonitorSettings, NodeError, NodeKey, PortMappingSettings, ProposerReorgs, StorageMode,
    WeakSubjectivity, WeakSubjectivityError,
    api::ApiServices,
    client_stats::ClientStats,
    genesis::GenesisSync,
    monitor::{MonitorMetrics, ValidatorMonitor},
    network::NetworkIdentity,
    slasher::{FoundSlashing, SlasherFeed},
    trusted_setup::TrustedSetupFile,
};

/// Where the node reaches its execution engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// The engine API endpoint, such as `http://127.0.0.1:8551`.
    pub url: String,
    /// File holding the hex JWT secret shared with the engine.
    pub jwt_secret: PathBuf,
    /// Factor the spec's call timeouts are multiplied by, for a slow engine.
    pub timeout_multiplier: u32,
}

impl EngineConfig {
    /// Connects to the engine with the shared secret.
    fn connect(&self) -> Result<ExecutionLayer, NodeError> {
        let text = fs::read_to_string(&self.jwt_secret).map_err(|error| NodeError::File {
            context: "reading the JWT secret",
            path: self.jwt_secret.clone(),
            error,
        })?;
        let secret = JwtSecret::from_hex(&text).map_err(|source| NodeError::Jwt {
            path: self.jwt_secret.clone(),
            source,
        })?;
        let client = EngineClient::new(&self.url, secret)
            .map_err(|source| NodeError::Engine {
                url: self.url.clone(),
                source,
            })?
            .with_timeout_multiplier(self.timeout_multiplier);
        info!(url = %self.url, "execution engine configured");
        Ok(ExecutionLayer::new(client))
    }
}

/// How the node joins the peer-to-peer network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSettings {
    /// TCP address libp2p listens on.
    pub listen_address: SocketAddr,
    /// UDP port libp2p QUIC listens on, on the listen address's interface; none runs TCP alone.
    pub quic_port: Option<u16>,
    /// Peers to dial at startup.
    pub boot_nodes: Vec<Multiaddr>,
    /// Peers the node aims to keep connected.
    pub target_peers: usize,
    /// Port mapping on the gateway, NAT-PMP then UPnP.
    pub port_mapping: PortMappingSettings,
    /// Custody groups to keep, at least the spec's custody requirement.
    pub custody_group_count: u64,
    /// Peer discovery; none relies on boot nodes alone.
    pub discovery: Option<DiscoverySettings>,
    /// Whether every attestation and sync committee subnet is joined, not only the node's own.
    pub subscribe_all_subnets: bool,
    /// Whether backfill batches wait for quiet moments of the slot, leaving the CPU to duties.
    pub backfill_rate_limiting: bool,
    /// Whether new blocks' columns are built from the engine's blob pool before peers send them.
    pub get_blobs: bool,
}

impl NetworkSettings {
    /// Starts the libp2p stack under the node's key, with the chain's gossip message identifiers.
    pub(crate) async fn start_p2p(
        &self,
        key: &NodeKey,
        message_ids: MessageIds,
    ) -> Result<(NetworkHandle, NetworkEvents), NodeError> {
        // TLS secures QUIC and Noise secures TCP, both under the node's secp256k1 identity.
        let mut p2p = NetworkConfig::new(key.keypair()).map_err(NodeError::Network)?;
        p2p.listen_addr = Multiaddr::from_tcp(self.listen_address);
        p2p.quic_listen_addr = self
            .quic_port
            .map(|port| Multiaddr::from_quic(SocketAddr::new(self.listen_address.ip(), port)));
        p2p.gossipsub.message_id = message_ids;
        swarm::start(p2p).await.map_err(NodeError::Network)
    }
}

/// Where a node with an empty database starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorSource {
    /// The network's genesis state.
    Genesis(GenesisState),
    /// A trusted block and its post-state, both SSZ, as a checkpoint sync obtains them.
    Checkpoint {
        /// The block's post-state.
        state: PathBuf,
        /// The signed block.
        block: PathBuf,
        /// The block's blob sidecars, an SSZ list, for a block of a fork with whole blobs.
        blobs: Option<PathBuf>,
    },
    /// A trusted beacon API to download the finalized block and its post-state from.
    Url {
        /// The beacon API, such as `http://127.0.0.1:5052`.
        url: String,
        /// Longest wait for one download.
        timeout: Duration,
    },
}

impl AnchorSource {
    /// Builds a chain on an empty database from this anchor.
    ///
    /// The anchor must be recent: a stale one may hide a long-range attack.
    /// See `is_within_weak_subjectivity_period` in the phase0 weak subjectivity guide.
    async fn open<P: Preset>(
        &self,
        chain_config: ChainConfig,
        database: ChainDatabase<P>,
        history: &HistorySettings,
        now_ms: u64,
    ) -> Result<Chain<P>, NodeError> {
        let mut blobs = Vec::new();
        let (state, block, genesis) = match self {
            Self::Genesis(source) => {
                return Self::genesis(source, chain_config, database, history, now_ms).await;
            }
            Self::Checkpoint {
                state,
                block,
                blobs: blob_file,
            } => {
                let state = SszFile::new(state, "reading the checkpoint state")
                    .decode(|bytes| BeaconState::<P>::decode_at(bytes, &chain_config))?;
                let block = SszFile::new(block, "reading the checkpoint block")
                    .decode(|bytes| SignedBeaconBlock::<P>::decode_at(bytes, &chain_config))?;
                if let Some(path) = blob_file {
                    blobs = SszFile::new(path, "reading the checkpoint blobs")
                        .decode(List::<BlobSidecar<P>, P::MaxBlobCommitmentsPerBlock>::decode)?
                        .into_vec();
                }
                (state, block, None)
            }
            Self::Url { url, timeout } => {
                info!(%url, "downloading the finalized checkpoint");
                let server = CheckpointServer::new(url, *timeout)?;
                let (state, block) = server.finalized::<P>(&chain_config).await?;
                // An archive rebuilds the states below the anchor from genesis, if the server has it.
                let genesis = match (database.mode(), &history.genesis) {
                    (StorageMode::Archive(_), None) => {
                        match server.genesis::<P>(&chain_config).await {
                            Ok(genesis) => Some(genesis),
                            Err(error) => {
                                warn!(%error, "no genesis state from the checkpoint server");
                                None
                            }
                        }
                    }
                    _ => None,
                };
                (state, block, genesis)
            }
        };
        history.check_recent(&state, &chain_config, now_ms)?;
        // The store refuses a block whose state root is not this state's.
        info!(slot = %block.slot(), fork = %block.fork_name(), "starting from a checkpoint");
        let mut chain = Chain::from_anchor(chain_config.clone(), state, &block, database)?;
        chain.import_anchor_blobs(&block, blobs)?;
        let genesis = match (&history.genesis, genesis) {
            (Some(source), _) => Some(source.load::<P>(&chain_config).await?),
            (None, downloaded) => downloaded,
        };
        Ok(match genesis {
            Some(genesis) => chain.with_genesis(&genesis)?,
            None => chain,
        })
    }

    /// Builds a chain from the genesis state, if the chain is young enough to sync from it.
    async fn genesis<P: Preset>(
        source: &GenesisState,
        chain_config: ChainConfig,
        database: ChainDatabase<P>,
        history: &HistorySettings,
        now_ms: u64,
    ) -> Result<Chain<P>, NodeError> {
        let genesis = source.load::<P>(&chain_config).await?;
        let sync = GenesisSync {
            allow_insecure: history.allow_insecure_genesis_sync,
        };
        sync.check(&genesis, &chain_config, now_ms)?;
        history.check_recent(&genesis, &chain_config, now_ms)?;
        info!(
            validators = genesis.validators().len(),
            fork = %genesis.fork_name(),
            "starting from genesis"
        );
        Ok(Chain::from_genesis(chain_config, genesis, database)?)
    }
}

/// How much history the node keeps and what anchors it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistorySettings {
    /// How much past state to keep.
    pub mode: StorageMode,
    /// A checkpoint the operator trusts, which the chain must pass through.
    pub weak_subjectivity: Option<WeakSubjectivity>,
    /// The genesis state, which lets an archive anchored later rebuild the states below its anchor.
    pub genesis: Option<GenesisState>,
    /// Whether to sync from genesis even after the blob window closed.
    pub allow_insecure_genesis_sync: bool,
    /// Whether a head older than its weak subjectivity period only warns instead of stopping.
    pub ignore_ws_check: bool,
}

impl HistorySettings {
    /// Refuses a state older than its weak subjectivity period, unless the operator ignores it.
    ///
    /// A node anchored on such a state may follow a long-range attacker's chain.
    /// See `is_within_weak_subjectivity_period` in the phase0 weak subjectivity guide.
    fn check_recent<P: Preset>(
        &self,
        state: &BeaconState<P>,
        chain_config: &ChainConfig,
        now_ms: u64,
    ) -> Result<(), NodeError> {
        let clock = SlotClock::new(
            state.genesis_time().saturating_mul(1000),
            chain_config.slot_duration_ms.max(1),
        );
        let current = clock.slot_at(now_ms).epoch::<P>();
        if WeakSubjectivity::is_within_period(state, chain_config, current) {
            return Ok(());
        }
        let stale = WeakSubjectivityError::Stale {
            state_epoch: state.current_epoch(),
            period: WeakSubjectivity::period(state, chain_config),
            current,
        };
        if self.ignore_ws_check {
            warn!(error = %stale, "running outside the weak subjectivity period, exposed to long-range attacks");
            return Ok(());
        }
        Err(ChainError::WeakSubjectivity(stale).into())
    }
}

/// An SSZ file, with what reading it is for.
#[derive(Clone, Copy, Debug)]
struct SszFile<'a> {
    /// Where the file is.
    path: &'a Path,
    /// What reading it is for, named in errors.
    context: &'static str,
}

impl<'a> SszFile<'a> {
    /// A file read for a purpose.
    const fn new(path: &'a Path, context: &'static str) -> Self {
        Self { path, context }
    }

    /// Reads the file and decodes it in the fork its slot falls in.
    fn decode<T>(
        self,
        decode: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
    ) -> Result<T, NodeError> {
        let bytes = fs::read(self.path).map_err(|error| NodeError::File {
            context: self.context,
            path: self.path.to_path_buf(),
            error,
        })?;
        decode(&bytes).map_err(|source| NodeError::Genesis {
            path: self.path.to_path_buf(),
            source,
        })
    }
}

/// Everything an operator chooses about a node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeConfig {
    /// Directory of the database; none keeps everything in memory.
    pub data_dir: Option<PathBuf>,
    /// Where to start when the database holds no anchor yet.
    pub anchor: Option<AnchorSource>,
    /// Address of the beacon API; none disables it.
    pub http_address: Option<SocketAddr>,
    /// Address of the Prometheus endpoint; none disables it.
    pub metrics_address: Option<SocketAddr>,
    /// The execution engine; none follows the chain optimistically.
    pub engine: Option<EngineConfig>,
    /// The peer-to-peer network; none runs the node alone.
    pub network: Option<NetworkSettings>,
    /// History, pruning, and weak subjectivity.
    pub history: HistorySettings,
    /// How the node builds blocks for its validators.
    pub proposer: ProposerSettings,
    /// The slasher's history and layout; none runs no slasher.
    pub slasher: Option<SlasherConfig>,
    /// Where the slasher keeps its history, and how often it looks.
    pub slasher_setup: SlasherSetup,
    /// How the chain thread runs: vote bounds, fast confirmation, light clients, and pruning.
    pub chain: ChainSettings,
    /// Database upkeep at startup and while running.
    pub database: DatabaseSettings,
    /// The browser origins the beacon API admits; none admits pages from its own address only.
    pub http_allow_origin: Option<Cors>,
    /// The certificate and key to serve the beacon API over TLS; none serves plain http.
    pub http_tls: Option<ApiTls>,
    /// The browser origins the metrics endpoint admits; none admits its own address only.
    pub metrics_allow_origin: Option<Cors>,
    /// Whether the node stops once its head reaches the wall clock.
    pub shutdown_after_sync: bool,
    /// The validators the node watches, and how closely.
    pub monitor: MonitorSettings,
    /// Where the node pushes its client stats; none pushes nothing.
    pub client_stats: Option<ClientStatsSettings>,
    /// A KZG trusted setup file to use in place of the mainnet one; none keeps the mainnet setup.
    pub trusted_setup: Option<PathBuf>,
}

/// The PEM files of the beacon API's TLS identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiTls {
    /// The certificate chain, the server's own certificate first.
    pub certificate: PathBuf,
    /// The private key, unencrypted, in PKCS#8, SEC 1 or PKCS#1 form.
    pub key: PathBuf,
}

/// How the node builds blocks for the validators it serves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposerSettings {
    /// The fee recipient of payloads whose validator named none.
    pub default_fee_recipient: ExecutionAddress,
    /// Builder API endpoints that sell payloads, such as a local relay multiplexer.
    pub builders: Vec<String>,
    /// How long builders get to answer, and what the node calls itself.
    pub builder_client: BuilderClientSettings,
    /// When the chain is too unhealthy to ask builders.
    pub builder_fallback: BuilderFallback,
    /// Graffiti of blocks whose request names none.
    pub graffiti: Option<Bytes32>,
    /// How long before a slot its payload is prepared; none prepares a third of a slot ahead.
    pub prepare_lookahead: Option<Duration>,
    /// Whether payloads are prepared for every slot, not only for prepared proposers.
    pub always_prepare_payload: bool,
    /// Whether proposals orphan a late, weak head.
    pub reorgs: ProposerReorgs,
}

/// How the node talks to builders.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderClientSettings {
    /// Deadline of a bid request; none keeps the spec's one second.
    pub header_timeout: Option<Duration>,
    /// The user agent each builder request names, when any.
    pub user_agent: Option<String>,
    /// Whether builders are spoken to in JSON alone, never SSZ.
    pub disable_ssz: bool,
}

impl BuilderClientSettings {
    /// Opens a client for each builder endpoint.
    pub(crate) fn connect(&self, urls: &[String]) -> Result<Vec<RelayClient>, NodeError> {
        let timeouts = RelayTimeouts {
            header: self.header_timeout.unwrap_or(RelayTimeouts::BID_DEADLINE),
            ..RelayTimeouts::DEFAULT
        };
        urls.iter()
            .map(|url| {
                let client = RelayClient::with_timeouts(url, timeouts).map_err(|error| {
                    NodeError::Builder {
                        url: url.clone(),
                        error: Box::new(error),
                    }
                })?;
                let client = if self.disable_ssz {
                    client.json_only()
                } else {
                    client
                };
                Ok(match &self.user_agent {
                    Some(agent) => client.with_user_agent(agent.clone()),
                    None => client,
                })
            })
            .collect()
    }
}

/// Thresholds past which the node stops asking builders, each overriding the preset default.
///
/// See the liveness failsafe section of the Bellatrix builder validator spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuilderFallback {
    /// Most missed slots tolerated in a row.
    pub skips: Option<u64>,
    /// Most missed slots tolerated over the last epoch.
    pub skips_per_epoch: Option<u64>,
    /// Most epochs tolerated since finality.
    pub epochs_since_finalization: Option<u64>,
    /// Whether builders are asked whatever the chain's health.
    pub disable_checks: bool,
}

impl BuilderFallback {
    /// The circuit breaker these thresholds describe for a preset.
    #[must_use]
    pub const fn breaker<P: Preset>(&self) -> CircuitBreaker {
        if self.disable_checks {
            return CircuitBreaker::NEVER;
        }
        let defaults = CircuitBreaker::for_preset::<P>();
        CircuitBreaker {
            max_consecutive_missed: match self.skips {
                Some(skips) => skips,
                None => defaults.max_consecutive_missed,
            },
            max_missed_per_epoch: match self.skips_per_epoch {
                Some(skips) => skips,
                None => defaults.max_missed_per_epoch,
            },
            max_finality_delay: match self.epochs_since_finalization {
                Some(epochs) => epochs,
                None => defaults.max_finality_delay,
            },
        }
    }
}

/// Where the slasher keeps its history, how often it looks for slashings, and whether it tells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlasherSetup {
    /// The history's directory; none keeps it beside the chain's, or in memory without one.
    pub directory: Option<PathBuf>,
    /// Time between two passes; none runs one each slot.
    pub update_period: Option<Duration>,
    /// Whether the evidence found is gossiped, not only pooled for this node's proposals.
    pub broadcast: bool,
}

impl Default for SlasherSetup {
    fn default() -> Self {
        // Evidence spreads by default, so any proposer can include it, not only this node's.
        Self {
            directory: None,
            update_period: None,
            broadcast: true,
        }
    }
}

/// Database upkeep at startup and while running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseSettings {
    /// Whether the store rewrites mostly dead segments as it goes.
    pub auto_compact: bool,
    /// Whether every eligible segment is rewritten once at startup.
    pub compact_on_start: bool,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        // Space is reclaimed as it goes, and startup does no extra work.
        Self {
            auto_compact: true,
            compact_on_start: false,
        }
    }
}

impl NodeConfig {
    /// Opens the database and builds the chain from its anchor, a checkpoint, or genesis.
    ///
    /// A configured weak subjectivity checkpoint then holds the chain to it.
    pub(crate) async fn open_chain<P: Preset>(
        &self,
        chain_config: ChainConfig,
        clock: &dyn Clock,
    ) -> Result<Chain<P>, NodeError> {
        let database = match &self.data_dir {
            Some(directory) => {
                let options = Options {
                    auto_compact: self.database.auto_compact,
                    ..Options::default()
                };
                ChainDatabase::open_with(&directory.join("chain"), chain_config.clone(), options)?
            }
            None => ChainDatabase::in_memory(chain_config.clone())?,
        }
        .with_mode(self.history.mode);
        if self.database.compact_on_start {
            info!("compacting the database");
            database.compact()?;
        }
        let chain = if database.has_anchor()? {
            info!("resuming from the database");
            let chain = Chain::resume(chain_config, database)?;
            // A node left off for months may resume past its weak subjectivity period.
            self.history.check_recent(
                chain.head_state()?.beacon(),
                chain.config(),
                clock.now_ms(),
            )?;
            chain
        } else {
            let anchor = self.anchor.as_ref().ok_or(NodeError::NoAnchor)?;
            // A downloaded anchor holds a whole state; boxing keeps this future small.
            Box::pin(anchor.open(chain_config, database, &self.history, clock.now_ms())).await?
        };
        Ok(match self.history.weak_subjectivity {
            Some(checkpoint) => {
                info!(%checkpoint, "holding the chain to a weak subjectivity checkpoint");
                chain.with_weak_subjectivity(checkpoint)?
            }
            None => chain,
        })
    }

    /// Watches the validators the operator named, with the monitor's own metrics.
    pub(crate) fn attach_monitor<P: Preset>(
        &self,
        chain: Chain<P>,
        registry: &Registry,
    ) -> Result<Chain<P>, NodeError> {
        let metrics = MonitorMetrics::register(registry).map_err(NodeError::Metrics)?;
        Ok(chain.with_monitor(ValidatorMonitor::new(&self.monitor, metrics)))
    }

    /// Starts pushing client stats, when an endpoint is configured.
    pub(crate) fn start_client_stats<P: Preset>(
        &self,
        chain: &ChainHandle<P>,
        clock: &Arc<dyn Clock>,
        metrics: NodeMetrics,
    ) -> Result<Option<JoinHandle<()>>, NodeError> {
        let Some(settings) = &self.client_stats else {
            return Ok(None);
        };
        let stats = ClientStats::new(
            settings,
            chain.clone(),
            Arc::clone(clock),
            metrics,
            self.data_dir.as_deref(),
        )
        .map_err(|source| NodeError::ClientStats {
            endpoint: settings.endpoint.clone(),
            source,
        })?;
        Ok(Some(task::spawn(stats.run())))
    }

    /// Starts the slasher, when enabled, with its history beside the chain's, and feeds it the chain.
    pub(crate) fn attach_slasher<P: Preset>(&self, chain: Chain<P>) -> Result<Chain<P>, NodeError> {
        let Some(settings) = self.slasher else {
            return Ok(chain);
        };
        let directory = match &self.slasher_setup.directory {
            Some(directory) => Some(directory.clone()),
            None => self.data_dir.as_ref().map(|data| data.join("slasher")),
        };
        let feed = SlasherFeed::start(settings, directory.as_deref())?
            .with_update_period(self.slasher_setup.update_period);
        Ok(chain.with_slasher(feed))
    }

    /// Has the chain hand the evidence its slasher finds to a broadcaster, unless kept local.
    ///
    /// # Returns
    ///
    /// The chain, and the broadcaster's end of the evidence channel when there is one.
    pub(crate) fn attach_slashing_broadcast<P: Preset>(
        &self,
        chain: Chain<P>,
    ) -> (Chain<P>, Option<UnboundedReceiver<FoundSlashing>>) {
        if self.slasher.is_none() || !self.slasher_setup.broadcast {
            return (chain, None);
        }
        let (broadcasts, found) = unbounded_channel();
        (chain.with_slashing_broadcast(broadcasts), Some(found))
    }

    /// The chain the node runs: opened, with its slasher, telemetry, event feed, and custody.
    ///
    /// The network identity fixes which columns the node custodies, so it opens here too.
    ///
    /// # Errors
    ///
    /// Fails when the chain, the slasher, or the network identity cannot open.
    pub(crate) async fn start_chain<P: Preset>(
        &self,
        chain_config: ChainConfig,
        clock: &dyn Clock,
        metrics: NodeMetrics,
        events: EventSender,
    ) -> Result<(Chain<P>, Option<(NodeKey, NetworkIdentity)>), NodeError> {
        // Every KZG check of the process reads one setup, so the operator's is installed first.
        if let Some(path) = &self.trusted_setup {
            TrustedSetupFile(path).trust()?;
        }
        // A checkpoint download holds a whole state; boxing keeps this future small.
        let chain = Box::pin(self.open_chain::<P>(chain_config, clock)).await?;
        let chain = self
            .attach_slasher(chain)?
            .with_settings(self.chain)
            .with_metrics(metrics)
            .with_events(events);
        let Some(settings) = &self.network else {
            return Ok((chain, None));
        };
        let identity = self.open_identity(settings)?;
        let columns = identity.1.sampling_columns::<P>(chain.config())?;
        Ok((chain.with_custody(columns), Some(identity)))
    }

    /// Loads or creates the node key, and derives the network identity from it.
    pub(crate) fn open_identity(
        &self,
        settings: &NetworkSettings,
    ) -> Result<(NodeKey, NetworkIdentity), NodeError> {
        // Without a data directory the key lives only as long as the process.
        let key = match &self.data_dir {
            Some(directory) => NodeKey::load_or_generate(&directory.join("network").join("key")),
            None => NodeKey::generate(),
        }
        .map_err(|error| NodeError::Io {
            context: "loading the node key",
            error,
        })?;
        let identity = NetworkIdentity {
            node_id: key.node_id(),
            custody_group_count: settings.custody_group_count,
            boot_nodes: settings.boot_nodes.clone(),
        };
        Ok((key, identity))
    }

    /// Connects to the engine, or stands in for one that keeps every payload optimistic.
    pub(crate) fn open_engine(&self) -> Result<ExecutionLayer, NodeError> {
        match &self.engine {
            Some(engine) => engine.connect(),
            None => {
                warn!("no execution engine: every payload stays optimistic");
                Ok(ExecutionLayer::disconnected())
            }
        }
    }

    /// Binds the beacon API and the metrics endpoint, when configured.
    ///
    /// Both stop serving once the shutdown signal fires.
    pub(crate) async fn start_servers<P: Preset>(
        &self,
        handle: &ChainHandle<P>,
        api: ApiServices<P>,
        registry: Registry,
        stopped: &watch::Receiver<bool>,
    ) -> Result<Vec<JoinHandle<()>>, NodeError> {
        let mut servers = Vec::new();
        if let Some(address) = self.http_address {
            // Block submissions name their fork in a header, which pages must be allowed to send.
            let cors = self
                .http_allow_origin
                .clone()
                .unwrap_or_else(|| Cors::local(address))
                .with_header("eth-consensus-version");
            let router = BeaconApi::router(handle.clone(), api).with_cors(cors);
            let mut server = Server::bind(address, router, ServerConfig::default())
                .await
                .map_err(|error| NodeError::Bind {
                    context: "binding the beacon API",
                    address,
                    error,
                })?;
            if let Some(tls) = &self.http_tls {
                let identity = ServerIdentity::from_pem_files(&tls.certificate, &tls.key)?;
                server = server.with_tls(identity);
            }
            info!(%address, tls = self.http_tls.is_some(), "beacon API listening");
            let signal = ShutdownSignal(stopped.clone());
            servers.push(task::spawn(server.serve(signal.wait())));
        }
        if let Some(address) = self.metrics_address {
            let cors = self
                .metrics_allow_origin
                .clone()
                .unwrap_or_else(|| Cors::local(address));
            let server = MetricsServer::bind_with_cors(address, registry, cors)
                .await
                .map_err(|error| NodeError::Bind {
                    context: "binding the metrics endpoint",
                    address,
                    error,
                })?;
            info!(%address, "metrics listening");
            let signal = ShutdownSignal(stopped.clone());
            servers.push(task::spawn(server.serve(signal.wait())));
        }
        Ok(servers)
    }
}

/// The node's shutdown flag, as one server watches it.
#[derive(Debug)]
struct ShutdownSignal(watch::Receiver<bool>);

impl ShutdownSignal {
    /// Completes once shutdown is signalled.
    async fn wait(mut self) {
        // A dropped sender also means shutdown, so either outcome ends the wait.
        let _signalled = self.0.wait_for(|stop| *stop).await;
    }
}
