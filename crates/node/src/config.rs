//! What an operator chooses about a node, and how each choice opens its component.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axiom_execution::{EngineClient, JwtSecret};
use axiom_http::{Server, ServerConfig};
use axiom_p2p::{
    Multiaddr,
    swarm::{self, NetworkConfig, NetworkEvents, NetworkHandle},
};
use axiom_ssz::DecodeError;
use axiom_telemetry::{MetricsServer, Registry};
use axiom_types::{
    ChainConfig, Preset,
    accessors::CoreState,
    combined::{BeaconState, SignedBeaconBlock},
};
use tokio::{
    sync::watch,
    task::{self, JoinHandle},
};
use tracing::{info, warn};

use crate::{
    BeaconApi, Chain, ChainDatabase, ChainHandle, DiscoverySettings, ExecutionLayer, NodeError,
    NodeKey, Publisher,
    network::{NetworkIdentity, NodeIdentity},
};

/// Where the node reaches its execution engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// The engine API endpoint, such as `http://127.0.0.1:8551`.
    pub url: String,
    /// File holding the hex JWT secret shared with the engine.
    pub jwt_secret: PathBuf,
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
        let client = EngineClient::new(&self.url, secret).map_err(|source| NodeError::Engine {
            url: self.url.clone(),
            source,
        })?;
        info!(url = %self.url, "execution engine configured");
        Ok(ExecutionLayer::new(client))
    }
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

impl NetworkSettings {
    /// Starts the libp2p stack under the node's key.
    pub(crate) async fn start_p2p(
        &self,
        key: &NodeKey,
    ) -> Result<(NetworkHandle, NetworkEvents), NodeError> {
        // Noise secures every connection under the node's secp256k1 identity.
        let mut p2p = NetworkConfig::new(key.keypair()).map_err(NodeError::Network)?;
        p2p.listen_addr = Multiaddr::from_tcp(self.listen_address);
        swarm::start(p2p).await.map_err(NodeError::Network)
    }
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

impl AnchorSource {
    /// Builds a chain on an empty database from this anchor.
    fn open<P: Preset>(
        &self,
        chain_config: ChainConfig,
        database: ChainDatabase<P>,
    ) -> Result<Chain<P>, NodeError> {
        match self {
            Self::Genesis(path) => {
                let genesis = SszFile::new(path, "reading the genesis state")
                    .decode(|bytes| BeaconState::<P>::decode_at(bytes, &chain_config))?;
                info!(
                    validators = genesis.validators().len(),
                    fork = %genesis.fork_name(),
                    "starting from genesis"
                );
                Ok(Chain::from_genesis(chain_config, genesis, database)?)
            }
            Self::Checkpoint { state, block } => {
                let state = SszFile::new(state, "reading the checkpoint state")
                    .decode(|bytes| BeaconState::<P>::decode_at(bytes, &chain_config))?;
                let block = SszFile::new(block, "reading the checkpoint block")
                    .decode(|bytes| SignedBeaconBlock::<P>::decode_at(bytes, &chain_config))?;
                // The store refuses a block whose state root is not this state's.
                info!(slot = %block.slot(), fork = %block.fork_name(), "starting from a checkpoint");
                Ok(Chain::from_anchor(chain_config, state, &block, database)?)
            }
        }
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
}

impl NodeConfig {
    /// Opens the database and builds the chain from its anchor or from genesis.
    pub(crate) fn open_chain<P: Preset>(
        &self,
        chain_config: ChainConfig,
    ) -> Result<Chain<P>, NodeError> {
        let database = match &self.data_dir {
            Some(directory) => ChainDatabase::open(&directory.join("chain"), chain_config.clone())?,
            None => ChainDatabase::in_memory(chain_config.clone())?,
        };
        if database.has_anchor()? {
            info!("resuming from the database");
            return Ok(Chain::resume(chain_config, database)?);
        }
        self.anchor
            .as_ref()
            .ok_or(NodeError::NoAnchor)?
            .open(chain_config, database)
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
        publisher: Arc<Publisher<P>>,
        identity: Option<Arc<NodeIdentity>>,
        registry: Registry,
        stopped: &watch::Receiver<bool>,
    ) -> Result<Vec<JoinHandle<()>>, NodeError> {
        let mut servers = Vec::new();
        if let Some(address) = self.http_address {
            let router = BeaconApi::router(handle.clone(), publisher, identity);
            let server = Server::bind(address, router, ServerConfig::default())
                .await
                .map_err(|error| NodeError::Bind {
                    context: "binding the beacon API",
                    address,
                    error,
                })?;
            info!(%address, "beacon API listening");
            let signal = ShutdownSignal(stopped.clone());
            servers.push(task::spawn(server.serve(signal.wait())));
        }
        if let Some(address) = self.metrics_address {
            let server = MetricsServer::bind(address, registry)
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
