//! The running node: every service started, wired, and stopped together.

use std::{
    fs, future::Future, marker::PhantomData, net::SocketAddr, path::PathBuf, sync::Arc,
    time::Duration,
};

use axiom_execution::{EngineClient, JwtSecret};
use axiom_http::{Server, ServerConfig};
use axiom_ssz::Ssz;
use axiom_telemetry::{MetricsServer, NodeMetrics, Registry};
use axiom_types::{BeaconState, ChainConfig, Preset};
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
    BeaconApi, Chain, ChainDatabase, ChainEvent, ChainHandle, Clock, ExecutionLayer, NodeError,
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

/// Everything an operator chooses about a node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeConfig {
    /// Directory of the database; none keeps everything in memory.
    pub data_dir: Option<PathBuf>,
    /// SSZ genesis state, used when the database holds no anchor yet.
    pub genesis_state: Option<PathBuf>,
    /// Address of the beacon API; none disables it.
    pub http_address: Option<SocketAddr>,
    /// Address of the Prometheus endpoint; none disables it.
    pub metrics_address: Option<SocketAddr>,
    /// The execution engine; none follows the chain optimistically.
    pub engine: Option<EngineConfig>,
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
        let chain = Self::open_chain(chain_config, &config)?.with_metrics(metrics.clone());
        let events = chain.subscribe();
        let slot_ms = chain.config().slot_duration_ms;
        let (handle, chain_thread) = ChainHandle::spawn(chain).map_err(|error| NodeError::Io {
            context: "spawning the chain thread",
            error,
        })?;

        // The engine, or a stand-in that keeps every payload optimistic.
        let execution = Arc::new(Self::open_engine(config.engine.as_ref())?.with_metrics(metrics));

        // Every server watches one shutdown signal.
        let (stop, stopped) = watch::channel(false);
        let mut servers: Vec<JoinHandle<()>> = Vec::new();
        if let Some(address) = config.http_address {
            let router = BeaconApi::router(handle.clone(), Arc::clone(&execution));
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
        let path = config.genesis_state.as_ref().ok_or(NodeError::NoAnchor)?;
        let bytes = fs::read(path).map_err(|error| NodeError::Io {
            context: "reading the genesis state",
            error,
        })?;
        let genesis = BeaconState::<P>::decode(&bytes).map_err(NodeError::Genesis)?;
        info!(
            validators = genesis.validators.len(),
            "starting from genesis"
        );
        Ok(Chain::from_genesis(chain_config, genesis, database)?)
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
