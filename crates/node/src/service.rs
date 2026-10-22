//! The running node: every service started, wired, and stopped together.

use std::{
    fs,
    future::Future,
    marker::PhantomData,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axiom_execution::{EngineClient, JwtSecret};
use axiom_http::{Server, ServerConfig};
use axiom_p2p::{
    Multiaddr,
    swarm::{self, NetworkConfig, NetworkEvents, NetworkHandle},
};
use axiom_ssz::Ssz;
use axiom_telemetry::{MetricsServer, NodeMetrics, Registry};
use axiom_types::{BeaconState, ChainConfig, ColumnIndex, Preset, SignedBeaconBlock, Slot};
use tokio::{
    sync::{
        broadcast::{self, error::RecvError},
        watch,
    },
    task::{self, JoinHandle},
    time,
};
use tracing::{info, warn};

use crate::{
    BeaconApi, Chain, ChainDatabase, ChainEvent, ChainHandle, Clock, DiscoverySettings,
    ExecutionLayer, NodeError, NodeKey, Publisher,
    network::{
        AttestationSubnets, Discovery, LocalRecord, NetworkIdentity, NetworkService, NetworkSetup,
        NodeIdentity,
    },
};

/// How many times per slot the fork choice clock advances.
///
/// Twelve ticks a slot is one a second on mainnet.
/// That is fine enough for every deadline inside a slot, and cheap.
const TICKS_PER_SLOT: u64 = 12;

/// Where the node reaches its execution engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// The engine API endpoint, such as `http://127.0.0.1:8551`.
    pub url: String,
    /// File holding the hex JWT secret shared with the engine.
    pub jwt_secret: PathBuf,
}

/// How the node joins the peer-to-peer network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSettings {
    /// TCP address libp2p listens on.
    pub listen_address: SocketAddr,
    /// Peers to dial at startup.
    pub boot_nodes: Vec<Multiaddr>,
    /// Custody groups to keep, at least the spec's custody requirement.
    pub custody_group_count: u64,
    /// Peer discovery; none relies on boot nodes alone.
    pub discovery: Option<DiscoverySettings>,
}

/// Where a node with an empty database starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorSource {
    /// An SSZ genesis state.
    Genesis(PathBuf),
    /// A trusted block and its post-state, both SSZ, as a checkpoint sync obtains them.
    Checkpoint {
        /// The block's post-state.
        state: PathBuf,
        /// The signed block.
        block: PathBuf,
    },
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
}

/// The running chain, as the services started after it see it.
#[derive(Clone, Copy, Debug)]
struct StartedChain<'a, P: Preset> {
    /// The chain thread.
    handle: &'a ChainHandle<P>,
    /// Genesis, in milliseconds since the Unix epoch.
    genesis_time_ms: u64,
}

/// A beacon node for one preset.
///
/// # Overview
///
/// ```text
///     ticker ─────┐                        ┌──> engine: fork choice updates
///     beacon api ─┼──> chain thread ──events┤
///                 │                        └──> logs and metrics
///     metrics <───┘ (scraped by Prometheus)
/// ```
///
/// Shutdown stops the servers, then the tasks, then drains the chain thread.
#[derive(Debug)]
pub struct Node<P: Preset> {
    /// The preset every component is built for.
    preset: PhantomData<P>,
}

impl<P: Preset> Node<P> {
    /// Runs a node until a shutdown future completes.
    ///
    /// # Errors
    ///
    /// Fails when a component cannot start, or the chain stops on its own.
    pub async fn run(
        chain_config: ChainConfig,
        config: NodeConfig,
        clock: Arc<dyn Clock>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), NodeError> {
        // Telemetry comes first, so every later component records into the same registry.
        let registry = Registry::new();
        let metrics = NodeMetrics::register(&registry).map_err(NodeError::Metrics)?;
        if let Err(error) = registry.register_process_metrics() {
            warn!(%error, "process metrics unavailable");
        }

        // The chain, from the database's anchor or from genesis.
        let mut chain = Self::open_chain(chain_config, &config)?.with_metrics(metrics.clone());

        // The network identity fixes which columns the node custodies.
        let identity = match &config.network {
            Some(settings) => {
                let identity = Self::open_identity(&config, settings)?;
                let columns = Self::custody_columns(chain.config(), &identity)?;
                chain = chain.with_custody(columns);
                Some(identity)
            }
            None => None,
        };
        let events = chain.subscribe();
        let genesis_time_ms = chain.store().genesis_time_ms();
        let slot_ms = chain.config().slot_duration_ms;
        let (handle, chain_thread) = ChainHandle::spawn(chain).map_err(|error| NodeError::Io {
            context: "spawning the chain thread",
            error,
        })?;

        // The engine, or a stand-in that keeps every payload optimistic.
        let execution =
            Arc::new(Self::open_engine(config.engine.as_ref())?.with_metrics(metrics.clone()));

        // The network, when configured, runs its own event loop.
        let network = match (identity, &config.network) {
            (Some(identity), Some(settings)) => {
                let started = StartedChain {
                    handle: &handle,
                    genesis_time_ms,
                };
                let services = (Arc::clone(&execution), Arc::clone(&clock), metrics);
                Some(Self::start_network(identity, settings, started, services).await?)
            }
            _ => None,
        };
        let (network, identity) = match network {
            Some((p2p, service, identity)) => (Some((p2p, service)), Some(Arc::new(identity))),
            None => (None, None),
        };

        // Proposed blocks go out on the network, when there is one, before import.
        let publisher = Arc::new(Publisher::new(
            handle.clone(),
            Arc::clone(&execution),
            Arc::clone(&clock),
            network.as_ref().map(|(p2p, _)| p2p.clone()),
        ));

        // Every server watches one shutdown signal.
        let (stop, stopped) = watch::channel(false);
        let servers =
            Self::start_servers(&config, &handle, publisher, identity, registry, &stopped).await?;

        // Background loops run until aborted.
        let ticker = task::spawn(Self::tick(handle.clone(), clock, slot_ms));
        let follower = task::spawn(Self::follow(handle.clone(), events, execution));

        shutdown.await;
        info!("shutting down");

        // Servers first, so no request reaches a chain that is going away.
        let _unwatched = stop.send(true);
        for server in servers {
            let _finished = server.await;
        }
        if let Some((p2p, service)) = network {
            // A swarm that already stopped needs no second notice.
            let _stopped = p2p.shutdown().await;
            service.abort();
            let _cancelled = service.await;
        }
        ticker.abort();
        follower.abort();
        let _cancelled = ticker.await;
        let _cancelled = follower.await;

        // The chain thread ends once the last handle is gone and its queue drains.
        drop(handle);
        task::spawn_blocking(move || chain_thread.join())
            .await
            .map_err(|_| NodeError::ChainStopped)?
            .map_err(|_| NodeError::ChainStopped)?;
        info!("stopped");
        Ok(())
    }

    /// Binds the beacon API and the metrics endpoint, when configured.
    async fn start_servers(
        config: &NodeConfig,
        handle: &ChainHandle<P>,
        publisher: Arc<Publisher<P>>,
        identity: Option<Arc<NodeIdentity>>,
        registry: Registry,
        stopped: &watch::Receiver<bool>,
    ) -> Result<Vec<JoinHandle<()>>, NodeError> {
        let mut servers = Vec::new();
        if let Some(address) = config.http_address {
            let router = BeaconApi::router(handle.clone(), publisher, identity);
            let server = Server::bind(address, router, ServerConfig::default())
                .await
                .map_err(|error| NodeError::Io {
                    context: "binding the beacon API",
                    error,
                })?;
            info!(%address, "beacon API listening");
            servers.push(task::spawn(server.serve(Self::signal(stopped.clone()))));
        }
        if let Some(address) = config.metrics_address {
            let server = MetricsServer::bind(address, registry)
                .await
                .map_err(|error| NodeError::Io {
                    context: "binding the metrics endpoint",
                    error,
                })?;
            info!(%address, "metrics listening");
            servers.push(task::spawn(server.serve(Self::signal(stopped.clone()))));
        }
        Ok(servers)
    }

    /// Starts libp2p and the network service over it.
    ///
    /// # Returns
    ///
    /// The network handle, for shutdown and publishing, the service's task, and the node's identity.
    async fn start_network(
        (key, identity): (NodeKey, NetworkIdentity),
        settings: &NetworkSettings,
        chain: StartedChain<'_, P>,
        (execution, clock, metrics): (Arc<ExecutionLayer>, Arc<dyn Clock>, NodeMetrics),
    ) -> Result<(NetworkHandle, JoinHandle<()>, NodeIdentity), NodeError> {
        // The record is stated for the wall clock's epoch, not the anchor's.
        let elapsed = clock.now_ms().saturating_sub(chain.genesis_time_ms);
        let (config, custody, genesis_validators_root) = chain
            .handle
            .run(|chain| {
                (
                    chain.config().clone(),
                    chain.custody().clone(),
                    chain.genesis_validators_root(),
                )
            })
            .await
            .map_err(|_| NodeError::ChainStopped)?;
        let epoch = Slot(elapsed / config.slot_duration_ms.max(1)).epoch::<P>();

        let (network, events) = Self::start_p2p(&key, settings).await?;
        let discovery = match &settings.discovery {
            Some(discovery) => {
                let record = LocalRecord {
                    tcp_port: settings.listen_address.port(),
                    fork_digest: config.fork_digest(genesis_validators_root, epoch),
                    epoch,
                    genesis_validators_root,
                    attnets: AttestationSubnets::new(identity.node_id).bits::<P>(epoch, &config),
                    custody_group_count: identity.custody_group_count,
                };
                let started = Discovery::start(&key, discovery, &config, record)
                    .await
                    .map_err(|error| NodeError::Io {
                        context: "starting discovery",
                        error,
                    })?;
                Some(started)
            }
            None => None,
        };
        let service = NetworkService::start(
            network.clone(),
            &identity,
            chain.handle.clone(),
            NetworkSetup {
                config,
                custody,
                genesis_time_ms: chain.genesis_time_ms,
                execution,
                clock,
                metrics,
                discovery,
            },
        )
        .await;
        let identity = service.identity();
        Ok((network, task::spawn(service.run(events)), identity))
    }

    /// Opens the database and builds the chain from its anchor or from genesis.
    fn open_chain(chain_config: ChainConfig, config: &NodeConfig) -> Result<Chain<P>, NodeError> {
        let database = match &config.data_dir {
            Some(directory) => ChainDatabase::open(&directory.join("chain"))?,
            None => ChainDatabase::in_memory()?,
        };
        if database.has_anchor()? {
            info!("resuming from the database");
            return Ok(Chain::resume(chain_config, database)?);
        }
        match config.anchor.as_ref().ok_or(NodeError::NoAnchor)? {
            AnchorSource::Genesis(path) => {
                let genesis: BeaconState<P> = Self::read_ssz(path, "reading the genesis state")?;
                info!(
                    validators = genesis.validators.len(),
                    "starting from genesis"
                );
                Ok(Chain::from_genesis(chain_config, genesis, database)?)
            }
            AnchorSource::Checkpoint { state, block } => {
                let state: BeaconState<P> = Self::read_ssz(state, "reading the checkpoint state")?;
                let block: SignedBeaconBlock<P> =
                    Self::read_ssz(block, "reading the checkpoint block")?;
                // The store refuses a block whose state root is not this state's.
                info!(slot = %block.message.slot, "starting from a checkpoint");
                Ok(Chain::from_anchor(chain_config, state, block, database)?)
            }
        }
    }

    /// Reads and decodes an SSZ file.
    fn read_ssz<T: Ssz>(path: &Path, context: &'static str) -> Result<T, NodeError> {
        let bytes = fs::read(path).map_err(|error| NodeError::Io { context, error })?;
        T::decode(&bytes).map_err(NodeError::Genesis)
    }

    /// Loads or creates the node key, and derives the network identity from it.
    fn open_identity(
        config: &NodeConfig,
        settings: &NetworkSettings,
    ) -> Result<(NodeKey, NetworkIdentity), NodeError> {
        // Without a data directory the key lives only as long as the process.
        let key = match &config.data_dir {
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

    /// The columns of every custody group the node keeps.
    ///
    /// See `get_custody_groups` and `compute_columns_for_custody_group` in the Fulu DAS spec.
    fn custody_columns(
        config: &ChainConfig,
        identity: &(NodeKey, NetworkIdentity),
    ) -> Result<Vec<ColumnIndex>, NodeError> {
        let (_, identity) = identity;
        let groups = identity
            .node_id
            .custody_groups(identity.custody_group_count, config)
            .map_err(NodeError::Custody)?;
        let mut columns = Vec::new();
        for group in groups {
            columns.extend(group.columns::<P>(config).map_err(NodeError::Custody)?);
        }
        Ok(columns)
    }

    /// Starts the libp2p stack.
    async fn start_p2p(
        key: &NodeKey,
        settings: &NetworkSettings,
    ) -> Result<(NetworkHandle, NetworkEvents), NodeError> {
        // Noise secures every connection under the node's secp256k1 identity.
        let mut p2p = NetworkConfig::new(key.keypair()).map_err(NodeError::Network)?;
        p2p.listen_addr = Multiaddr::from_tcp(settings.listen_address);
        swarm::start(p2p).await.map_err(NodeError::Network)
    }

    /// Connects to the engine, when one is configured.
    fn open_engine(engine: Option<&EngineConfig>) -> Result<ExecutionLayer, NodeError> {
        let Some(engine) = engine else {
            warn!("no execution engine: every payload stays optimistic");
            return Ok(ExecutionLayer::disconnected());
        };
        let text = fs::read_to_string(&engine.jwt_secret).map_err(|error| NodeError::Io {
            context: "reading the JWT secret",
            error,
        })?;
        let secret = JwtSecret::from_hex(&text).map_err(NodeError::Jwt)?;
        let client = EngineClient::new(&engine.url, secret).map_err(NodeError::Engine)?;
        info!(url = %engine.url, "execution engine configured");
        Ok(ExecutionLayer::new(client))
    }

    /// Advances the fork choice clock at a fixed fraction of the slot, forever.
    async fn tick(chain: ChainHandle<P>, clock: Arc<dyn Clock>, slot_ms: u64) {
        let period = (slot_ms / TICKS_PER_SLOT).max(1);
        loop {
            let now = clock.now_ms();
            match chain.run(move |chain| chain.on_tick(now)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "tick failed"),
                Err(_) => return,
            }
            // Sleep to the next boundary, so ticks stay aligned with slot starts.
            let next = (now / period + 1) * period;
            time::sleep(Duration::from_millis(next.saturating_sub(clock.now_ms()))).await;
        }
    }

    /// Tells the engine about every new head and feeds its verdicts back, forever.
    async fn follow(
        chain: ChainHandle<P>,
        mut events: broadcast::Receiver<ChainEvent>,
        execution: Arc<ExecutionLayer>,
    ) {
        loop {
            match events.recv().await {
                Ok(ChainEvent::Head(head)) => {
                    let Some(verdict) = execution.update_forkchoice::<P>(head.execution).await
                    else {
                        continue;
                    };
                    let root = head.root;
                    let applied = chain
                        .run(move |chain| chain.on_payload_verdict(root, verdict))
                        .await;
                    match applied {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => warn!(%error, "engine verdict not applied"),
                        Err(_) => return,
                    }
                }
                Ok(ChainEvent::Reorg { .. } | ChainEvent::Finalized(_)) => {}
                // Falling behind skips stale heads; the next one supersedes them anyway.
                Err(RecvError::Lagged(skipped)) => warn!(skipped, "engine follower lagged"),
                Err(RecvError::Closed) => return,
            }
        }
    }

    /// A future that completes once shutdown is signalled.
    async fn signal(mut stopped: watch::Receiver<bool>) {
        // A dropped sender also means shutdown, so either outcome ends the wait.
        let _signalled = stopped.wait_for(|stop| *stop).await;
    }
}
