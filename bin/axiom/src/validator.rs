//! The validator command: keys from a directory, duties through beacon nodes, until a signal.

use std::{
    collections::BTreeSet,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use axiom_beacon_json::api::Genesis;
use axiom_http::{Client, ClientConfig, Cors, Endpoint, HttpError};
use axiom_json::Data;
use axiom_node::SystemClock;
use axiom_telemetry::{LogConfig, MetricsServer, Registry, RegistryError};
use axiom_types::{
    BlsPubkey, ChainConfig, ExecutionAddress, Gnosis, Mainnet, Minimal, Preset, Root, SlotClock,
    Version,
};
use axiom_validator::{
    beacon::{ApiTopic, BeaconClient, BeaconError, BeaconNodes},
    duties::{ClientSettings, DutyContext, SlotTimer, ValidatorClient},
    keymanager::{DirectoryError, KeyDirectory, KeySource, Keymanager, LoadedKey},
    metrics::ValidatorMetrics,
    protection::{ProtectionError, SlashingDatabase},
    signing::{
        RemoteError, RemoteSigner, SignError, SigningContext, SigningGuard, ValidatorSigner,
    },
    validators::{
        DEFAULT_GAS_LIMIT, Graffiti, GraffitiFile, ProposerDefaults, ValidatorSettings,
        ValidatorStore,
    },
};
use thiserror::Error;
use tokio::{runtime::Builder, task, time};
use tracing::{info, warn};

use crate::{
    cli::{Cli, CliError, log::LogFlags},
    run::{PresetName, Run},
};

/// The usage text of the validator command.
pub(crate) const VALIDATOR_USAGE: &str = "\
axiom validator: perform duties for the keys in a directory

USAGE:
    axiom validator [OPTIONS]

OPTIONS:
    --network <NAME>               mainnet, sepolia, holesky, hoodi, gnosis, chiado, or minimal
    --config <FILE>                chain config YAML; its PRESET_BASE picks the preset
    --datadir <DIR>                keys, definitions, and slashing protection [default: validator]
    --beacon-node <URLS>           beacon API endpoints, comma-separated or repeated,
                                   in order of preference [default: http://127.0.0.1:5052]
    --proposer-nodes <URLS>        beacon API endpoints that build and publish blocks first
    --broadcast <TOPICS>           topics sent to every beacon node: attestations, blocks,
                                   subscriptions, sync-committee, or none [default: subscriptions]
    --remote-signer <URL>          also sign with every key a remote signer holds
    --init-slashing-protection     create the slashing protection database if it is missing
    --fee-recipient <ADDR>         default fee recipient, also --suggested-fee-recipient
                                   [default: the zero address]
    --gas-limit <GAS>              default gas limit [default: 60000000]
    --graffiti <TEXT>              default graffiti, up to 32 bytes
    --graffiti-file <FILE>         graffiti per key, read before each proposal
    --graffiti-append [<BOOL>]     let the beacon node append client versions [default: true]
    --builder                      register with external builders, also --builder-proposals
    --builder-boost-factor <N>     percentage weighing a builder's bid against the local payload
    --prefer-builder-proposals     always prefer a builder's bid
    --builder-registration-timestamp-override <UNIX>
                                   timestamp every builder registration carries
    --validator-registration-batch-size <N>
                                   registrations per request [default: 500]
    --disable-attesting            skip attestation and sync committee duties
    --distributed                  combine selection proofs through a distributed validator middleware
    --doppelganger-epochs <N>      epochs new keys wait before signing [default: 2]
    --keymanager-address <ADDR>    serve the keymanager API
    --http-token-path <FILE>       keymanager API token [default: DIR/api-token.txt]
    --http-allow-origin <ORIGIN>   origin browsers may call the keymanager API from, or *
    --metrics                      serve Prometheus metrics
    --metrics-address <IP>         metrics address [default: 127.0.0.1]
    --metrics-port <PORT>          metrics port [default: 5064]
    --metrics-allow-origin <ORIGIN>
                                   origin browsers may read metrics from, or *
    --log, --log-format, --logfile-*
                                   logging, as for the beacon node; files go to DIR/logs
    -h, --help                     print this help
";

/// Default beacon node, the beacon API's usual address.
const DEFAULT_BEACON_NODE: &str = "http://127.0.0.1:5052";

/// Default metrics port: the validator client port next to the beacon node's 5054.
const DEFAULT_METRICS_PORT: u16 = 5064;

/// Time between attempts to reach a beacon node for genesis.
const GENESIS_RETRY: Duration = Duration::from_secs(5);

/// A resolved validator client run.
#[derive(Debug)]
pub(crate) struct ValidatorRun {
    /// The preset.
    preset: PresetName,
    /// The chain.
    chain: ChainConfig,
    /// The key directory.
    datadir: PathBuf,
    /// Beacon nodes, in order of preference.
    beacon_nodes: Vec<String>,
    /// Beacon nodes tried first for blocks.
    proposer_nodes: Vec<String>,
    /// Topics published on every beacon node.
    broadcast: BTreeSet<ApiTopic>,
    /// A remote signer whose keys are used too.
    remote_signer: Option<String>,
    /// Whether a missing slashing protection database may be created.
    init_slashing_protection: bool,
    /// Proposal defaults.
    defaults: ProposerDefaults,
    /// A file of graffiti per key.
    graffiti_file: Option<PathBuf>,
    /// Client behaviour.
    settings: ClientSettings,
    /// Where the keymanager API listens, if anywhere.
    keymanager: Option<SocketAddr>,
    /// The keymanager API token file, instead of the one in the data directory.
    token_path: Option<PathBuf>,
    /// Who may call the keymanager API from a browser, instead of its own address.
    keymanager_origin: Option<Cors>,
    /// Where metrics are served, if anywhere.
    metrics: Option<SocketAddr>,
    /// Who may read metrics from a browser, instead of their own address.
    metrics_origin: Option<Cors>,
    /// The logger.
    log: LogConfig,
}

/// What the validator command line asks for.
#[derive(Debug)]
pub(crate) enum ValidatorCommand {
    /// Print the usage text.
    Help,
    /// Run the client.
    Run(Box<ValidatorRun>),
}

/// Why the validator client stopped with an error.
#[derive(Debug, Error)]
pub(crate) enum ValidatorError {
    /// The runtime or a socket failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// A URL is malformed.
    #[error("URL: {0}")]
    Url(#[from] HttpError),
    /// No beacon node is usable.
    #[error("beacon node: {0}")]
    Beacon(#[from] BeaconError),
    /// The beacon node serves another chain than the configuration.
    #[error("beacon node genesis fork version {node}, configuration {config}")]
    WrongChain {
        /// The node's genesis fork version.
        node: Version,
        /// The configuration's.
        config: Version,
    },
    /// Slashing protection cannot open.
    #[error("slashing protection: {0}")]
    Protection(#[from] ProtectionError),
    /// The slashing protection database is missing while keys exist.
    #[error(
        "no slashing protection database in {}: restore it, or start once with --init-slashing-protection if it never existed",
        path.display()
    )]
    NoSlashingProtection {
        /// Where the database should be.
        path: PathBuf,
    },
    /// A key is missing from the slashing protection database.
    #[error(
        "validator {0} is not in the slashing protection database: import its history, or start with --init-slashing-protection"
    )]
    Unregistered(BlsPubkey),
    /// The key directory cannot load.
    #[error("keys: {0}")]
    Directory(#[from] DirectoryError),
    /// A key cannot be added.
    #[error("key: {0}")]
    Sign(#[from] SignError),
    /// The remote signer cannot list its keys.
    #[error("remote signer: {0}")]
    Remote(#[from] RemoteError),
    /// The metrics cannot be registered.
    #[error("metrics: {0}")]
    Metrics(#[from] RegistryError),
}

impl ValidatorCommand {
    /// Parses the flags after the word validator.
    ///
    /// # Errors
    ///
    /// Fails on an unknown flag, a missing value, a value that does not parse,
    /// or flags that need or exclude each other.
    pub(crate) fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
        let flags = ValidatorFlags::parse(arguments)?;
        if flags.help {
            return Ok(Self::Help);
        }
        flags.resolve().map(|run| Self::Run(Box::new(run)))
    }

    /// Runs the command.
    ///
    /// # Errors
    ///
    /// Fails when the client cannot start.
    pub(crate) fn execute(self) -> Result<(), ValidatorError> {
        match self {
            Self::Help => {
                let _unwritable = write!(io::stdout(), "{VALIDATOR_USAGE}");
                Ok(())
            }
            Self::Run(run) => run.execute(),
        }
    }
}

/// The validator flags as given, before they are checked against each other.
#[derive(Debug)]
struct ValidatorFlags {
    /// Whether help was asked for.
    help: bool,
    /// The network name.
    network: Option<String>,
    /// The config file.
    config: Option<PathBuf>,
    /// The data directory.
    datadir: Option<PathBuf>,
    /// Beacon node URLs.
    beacon_nodes: Vec<String>,
    /// Proposer node URLs.
    proposer_nodes: Vec<String>,
    /// Broadcast topics.
    broadcast: Option<BTreeSet<ApiTopic>>,
    /// Remote signer URL.
    remote_signer: Option<String>,
    /// Whether a missing database may be created.
    init_slashing_protection: bool,
    /// Proposal defaults, apart from graffiti.
    defaults: ProposerDefaults,
    /// Default graffiti.
    graffiti: Option<Graffiti>,
    /// Graffiti file.
    graffiti_file: Option<PathBuf>,
    /// Client behaviour.
    settings: ClientSettings,
    /// Keymanager address.
    keymanager: Option<SocketAddr>,
    /// Keymanager token file.
    token_path: Option<PathBuf>,
    /// Keymanager browser origin.
    keymanager_origin: Option<Cors>,
    /// Whether metrics are served.
    metrics: bool,
    /// Metrics address.
    metrics_address: Option<IpAddr>,
    /// Metrics port.
    metrics_port: Option<u16>,
    /// Metrics browser origin.
    metrics_origin: Option<Cors>,
    /// Logging, to the terminal and to files.
    log: LogFlags,
}

impl Default for ValidatorFlags {
    fn default() -> Self {
        Self {
            help: false,
            network: None,
            config: None,
            datadir: None,
            beacon_nodes: Vec::new(),
            proposer_nodes: Vec::new(),
            broadcast: None,
            remote_signer: None,
            init_slashing_protection: false,
            defaults: ProposerDefaults {
                gas_limit: DEFAULT_GAS_LIMIT,
                ..ProposerDefaults::default()
            },
            graffiti: None,
            graffiti_file: None,
            settings: ClientSettings::default(),
            keymanager: None,
            token_path: None,
            keymanager_origin: None,
            metrics: false,
            metrics_address: None,
            metrics_port: None,
            metrics_origin: None,
            log: LogFlags::default(),
        }
    }
}

impl ValidatorFlags {
    /// Reads every flag, without checking how they combine.
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
        let mut flags = Self::default();
        let mut arguments = arguments.into_iter().peekable();
        while let Some(flag) = arguments.next() {
            // The one flag whose value is optional takes the next word only when it is a boolean.
            if flag == "--graffiti-append" {
                let value = arguments.next_if(|word| word == "true" || word == "false");
                flags.settings.preserve_graffiti = value.is_some_and(|word| word == "false");
                continue;
            }
            let mut value =
                |name: &'static str| arguments.next().ok_or(CliError::MissingValue(name));
            let known = flags.read_client(&flag, &mut value)?
                || flags.read_proposals(&flag, &mut value)?
                || flags.read_duties(&flag, &mut value)?
                || flags.read_servers(&flag, &mut value)?;
            if !known {
                return Err(CliError::UnknownFlag(flag));
            }
        }
        Ok(flags)
    }

    /// Reads a flag of the chain, the beacon nodes, the keys, or the logs.
    fn read_client(
        &mut self,
        flag: &str,
        value: &mut impl FnMut(&'static str) -> Result<String, CliError>,
    ) -> Result<bool, CliError> {
        match flag {
            "-h" | "--help" => self.help = true,
            "--network" => self.network = Some(value("--network")?),
            "--config" => self.config = Some(value("--config")?.into()),
            "--datadir" => self.datadir = Some(value("--datadir")?.into()),
            "--beacon-node" | "--beacon-nodes" => {
                self.beacon_nodes
                    .extend(Self::list(&value("--beacon-node")?));
            }
            "--proposer-nodes" => {
                self.proposer_nodes
                    .extend(Self::list(&value("--proposer-nodes")?));
            }
            "--broadcast" => {
                let text = value("--broadcast")?;
                let topics = ApiTopic::parse_list(&text).map_err(|_| CliError::InvalidValue {
                    flag: "--broadcast",
                    value: text,
                })?;
                self.broadcast = Some(topics);
            }
            "--remote-signer" => self.remote_signer = Some(value("--remote-signer")?),
            "--init-slashing-protection" => self.init_slashing_protection = true,
            _ => return self.log.read_with(flag, &mut *value),
        }
        Ok(true)
    }

    /// Reads a flag of the proposal defaults.
    fn read_proposals(
        &mut self,
        flag: &str,
        value: &mut impl FnMut(&'static str) -> Result<String, CliError>,
    ) -> Result<bool, CliError> {
        let defaults = &mut self.defaults;
        match flag {
            "--fee-recipient" | "--suggested-fee-recipient" => {
                let text = value("--fee-recipient")?;
                let bytes = <[u8; 20]>::from_data(&text).map_err(|_| CliError::InvalidValue {
                    flag: "--fee-recipient",
                    value: text,
                })?;
                defaults.fee_recipient = ExecutionAddress(bytes);
            }
            "--gas-limit" => {
                defaults.gas_limit = Self::parsed("--gas-limit", value("--gas-limit")?)?;
            }
            "--graffiti" => {
                let text = value("--graffiti")?;
                let graffiti = Graffiti::parse(&text).map_err(|_| CliError::InvalidValue {
                    flag: "--graffiti",
                    value: text,
                })?;
                self.graffiti = Some(graffiti);
            }
            "--graffiti-file" => self.graffiti_file = Some(value("--graffiti-file")?.into()),
            "--builder" | "--builder-proposals" => defaults.builder = true,
            "--builder-boost-factor" => {
                let text = value("--builder-boost-factor")?;
                defaults.builder_boost_factor = Some(Self::parsed("--builder-boost-factor", text)?);
            }
            "--prefer-builder-proposals" => defaults.prefer_builder_proposals = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Reads a flag of how duties run.
    fn read_duties(
        &mut self,
        flag: &str,
        value: &mut impl FnMut(&'static str) -> Result<String, CliError>,
    ) -> Result<bool, CliError> {
        let settings = &mut self.settings;
        match flag {
            "--builder-registration-timestamp-override" => {
                let name = "--builder-registration-timestamp-override";
                settings.registration_timestamp = Some(Self::parsed(name, value(name)?)?);
            }
            "--validator-registration-batch-size" => {
                let name = "--validator-registration-batch-size";
                let text = value(name)?;
                let size: usize = Self::parsed(name, text.clone())?;
                // A batch of nothing would never send a registration.
                if size == 0 {
                    return Err(CliError::InvalidValue {
                        flag: name,
                        value: text,
                    });
                }
                settings.registration_batch_size = size;
            }
            "--disable-attesting" => settings.disable_attesting = true,
            "--distributed" => settings.distributed = true,
            "--doppelganger-epochs" => {
                let text = value("--doppelganger-epochs")?;
                settings.doppelganger_epochs = Self::parsed("--doppelganger-epochs", text)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Reads a flag of the keymanager API or the metrics endpoint.
    fn read_servers(
        &mut self,
        flag: &str,
        value: &mut impl FnMut(&'static str) -> Result<String, CliError>,
    ) -> Result<bool, CliError> {
        match flag {
            "--keymanager-address" => {
                let text = value("--keymanager-address")?;
                self.keymanager = Some(Self::parsed("--keymanager-address", text)?);
            }
            "--http-token-path" => self.token_path = Some(value("--http-token-path")?.into()),
            "--http-allow-origin" => {
                let text = value("--http-allow-origin")?;
                self.keymanager_origin = Some(Self::origin("--http-allow-origin", text)?);
            }
            "--metrics" => self.metrics = true,
            "--metrics-address" => {
                let text = value("--metrics-address")?;
                self.metrics_address = Some(Self::parsed("--metrics-address", text)?);
            }
            "--metrics-port" => {
                self.metrics_port = Some(Self::parsed("--metrics-port", value("--metrics-port")?)?);
            }
            "--metrics-allow-origin" => {
                let text = value("--metrics-allow-origin")?;
                self.metrics_origin = Some(Self::origin("--metrics-allow-origin", text)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Checks how the flags combine, and fills in every default.
    fn resolve(self) -> Result<ValidatorRun, CliError> {
        self.check()?;
        let (preset, chain) = Cli::choose_chain(self.network.as_deref(), self.config.as_deref())?;
        let mut beacon_nodes = self.beacon_nodes;
        if beacon_nodes.is_empty() {
            beacon_nodes.push(DEFAULT_BEACON_NODE.to_owned());
        }
        let metrics = self.metrics.then(|| {
            SocketAddr::new(
                self.metrics_address
                    .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                self.metrics_port.unwrap_or(DEFAULT_METRICS_PORT),
            )
        });
        let datadir = self.datadir.unwrap_or_else(|| PathBuf::from("validator"));
        // Logs land beside the keys unless told otherwise.
        let log = self.log.resolve(Some(datadir.join("logs")), "validator");
        Ok(ValidatorRun {
            preset,
            chain,
            datadir,
            beacon_nodes,
            proposer_nodes: self.proposer_nodes,
            broadcast: self.broadcast.unwrap_or_else(ApiTopic::defaults),
            remote_signer: self.remote_signer,
            init_slashing_protection: self.init_slashing_protection,
            defaults: ProposerDefaults {
                graffiti: self.graffiti.unwrap_or_default(),
                ..self.defaults
            },
            graffiti_file: self.graffiti_file,
            settings: self.settings,
            keymanager: self.keymanager,
            token_path: self.token_path,
            keymanager_origin: self.keymanager_origin,
            metrics,
            metrics_origin: self.metrics_origin,
            log,
        })
    }

    /// Refuses refining flags without their base flag, and flags that contradict each other.
    fn check(&self) -> Result<(), CliError> {
        let requirements = [
            (
                self.metrics_address.is_some(),
                "--metrics-address",
                self.metrics,
                "--metrics",
            ),
            (
                self.metrics_port.is_some(),
                "--metrics-port",
                self.metrics,
                "--metrics",
            ),
            (
                self.metrics_origin.is_some(),
                "--metrics-allow-origin",
                self.metrics,
                "--metrics",
            ),
            (
                self.token_path.is_some(),
                "--http-token-path",
                self.keymanager.is_some(),
                "--keymanager-address",
            ),
        ];
        for (given, flag, present, needs) in requirements {
            if given && !present {
                return Err(CliError::Requires { flag, needs });
            }
        }
        let conflicts = [
            (
                self.graffiti.is_some() && self.graffiti_file.is_some(),
                "--graffiti",
                "--graffiti-file",
            ),
            (
                self.defaults.builder_boost_factor.is_some()
                    && self.defaults.prefer_builder_proposals,
                "--builder-boost-factor",
                "--prefer-builder-proposals",
            ),
        ];
        for (both, flag, other) in conflicts {
            if both {
                return Err(CliError::Conflicts { flag, other });
            }
        }
        Ok(())
    }

    /// The URLs of a comma-separated list.
    fn list(text: &str) -> impl Iterator<Item = String> + '_ {
        text.split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(ToOwned::to_owned)
    }

    /// Any flag whose value parses from text.
    fn parsed<T: FromStr>(flag: &'static str, value: String) -> Result<T, CliError> {
        value
            .parse()
            .map_err(|_| CliError::InvalidValue { flag, value })
    }

    /// A cross-origin policy flag.
    fn origin(flag: &'static str, value: String) -> Result<Cors, CliError> {
        Cors::parse(&value).map_err(|_| CliError::InvalidValue { flag, value })
    }
}

impl ValidatorRun {
    /// Starts logging and the runtime, then runs the client until a signal stops it.
    fn execute(self) -> Result<(), ValidatorError> {
        if let Err(error) = self.log.init() {
            let _unwritable = writeln!(io::stderr(), "error: logging: {error}");
        }
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name("axiom-validator")
            .build()?;
        runtime.block_on(async move {
            // The preset is a compile-time choice, so each one is its own client.
            match self.preset {
                PresetName::Mainnet => self.run::<Mainnet>().await,
                PresetName::Minimal => self.run::<Minimal>().await,
                PresetName::Gnosis => self.run::<Gnosis>().await,
            }
        })
    }

    /// Wires the client together and runs it.
    async fn run<P: Preset>(self) -> Result<(), ValidatorError> {
        let registry = Registry::new();
        registry.register_process_metrics()?;
        let metrics = ValidatorMetrics::register(&registry)?;

        let nodes =
            Arc::new(Self::nodes(&self.beacon_nodes)?.with_broadcast(self.broadcast.clone()));
        let genesis = Self::genesis(&nodes).await;
        if genesis.genesis_fork_version != self.chain.genesis_fork_version {
            return Err(ValidatorError::WrongChain {
                node: genesis.genesis_fork_version,
                config: self.chain.genesis_fork_version,
            });
        }

        // Keys first, so slashing protection knows whether any exist.
        let directory = Arc::new(KeyDirectory::open(&self.datadir)?);
        let mut keys = directory.load()?;
        if let Some(url) = &self.remote_signer {
            let client = Arc::new(Client::new(Endpoint::parse(url)?, ClientConfig::default()));
            for pubkey in RemoteSigner::public_keys(&client).await? {
                keys.push(LoadedKey {
                    signer: ValidatorSigner::Remote(RemoteSigner::new(Arc::clone(&client), pubkey)),
                    source: KeySource::Remote(url.clone()),
                    settings: ValidatorSettings::default(),
                });
            }
        }
        let protection = Arc::new(self.protection(&keys, genesis.genesis_validators_root)?);

        let config = Arc::new(self.chain.clone());
        let context = SigningContext::new(Arc::clone(&config), genesis.genesis_validators_root);
        let mut store = ValidatorStore::new(SigningGuard::new(context, protection), self.defaults)
            .with_metrics(metrics.clone());
        if let Some(path) = &self.graffiti_file {
            store = store.with_graffiti_file(GraffitiFile::new(path.clone()));
        }
        let store = Arc::new(store);
        let doppelganger = self.settings.doppelganger_epochs > 0;
        for key in keys {
            let pubkey = store.add(key.signer, !doppelganger)?;
            let settings = key.settings;
            store.edit_overrides(&pubkey, |overrides| *overrides = settings);
        }
        info!(
            keys = store.pubkeys().len(),
            doppelganger, "validator keys loaded"
        );

        let slots = SlotClock::new(genesis.genesis_time * 1000, config.slot_duration_ms.max(1));
        let timer = SlotTimer::new(Arc::new(SystemClock), slots);
        let mut services = Vec::new();
        if let Some(address) = self.metrics {
            let cors = self
                .metrics_origin
                .clone()
                .unwrap_or_else(|| Cors::local(address));
            let server = MetricsServer::bind_with_cors(address, registry, cors).await?;
            info!(%address, "metrics listening");
            services.push(task::spawn(server.serve(Run::shutdown_signal())));
        }
        if let Some(address) = self.keymanager {
            let token = match &self.token_path {
                Some(path) => KeyDirectory::token_at(path)?,
                None => directory.api_token()?,
            };
            let cors = self
                .keymanager_origin
                .clone()
                .unwrap_or_else(|| Cors::local(address));
            let server = Keymanager::<P>::new(
                Arc::clone(&store),
                Arc::clone(&directory),
                &token,
                timer.clone(),
                doppelganger,
            )
            .bind(address, cors)
            .await?;
            info!(%address, "keymanager API listening");
            services.push(task::spawn(server.serve(Run::shutdown_signal())));
        }
        let mut duties =
            DutyContext::<P>::new(store, nodes, config, timer, self.settings).with_metrics(metrics);
        if !self.proposer_nodes.is_empty() {
            let proposers = Self::nodes(&self.proposer_nodes)?.with_broadcast(self.broadcast);
            duties = duties.with_proposer_nodes(Arc::new(proposers));
        }
        ValidatorClient::new(duties)
            .run(Run::shutdown_signal())
            .await;
        for service in services {
            service.abort();
            let _aborted = service.await;
        }
        Ok(())
    }

    /// Opens slashing protection, creating it only when that cannot lose history.
    ///
    /// A missing database is created when no key exists yet, or when the operator asks.
    /// Otherwise it may have been misplaced, and signing without it risks a slashing.
    /// Every key must already be registered, unless the operator asks to register them.
    fn protection(
        &self,
        keys: &[LoadedKey],
        genesis_validators_root: Root,
    ) -> Result<SlashingDatabase, ValidatorError> {
        let path = self.datadir.join("slashing_protection");
        let exists = Self::database_exists(&path)?;
        if !exists && !self.init_slashing_protection && !keys.is_empty() {
            return Err(ValidatorError::NoSlashingProtection { path });
        }
        let protection = SlashingDatabase::open(&path, genesis_validators_root)?;
        if !self.init_slashing_protection {
            let unregistered = keys
                .iter()
                .map(|key| key.signer.pubkey())
                .find(|pubkey| !protection.is_registered(pubkey));
            if let Some(pubkey) = unregistered {
                return Err(ValidatorError::Unregistered(pubkey));
            }
        }
        Ok(protection)
    }

    /// Whether a slashing protection database exists at a path.
    fn database_exists(path: &Path) -> Result<bool, ValidatorError> {
        match SlashingDatabase::open_existing(path) {
            Ok(_) => Ok(true),
            Err(ProtectionError::Uninitialized) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// A set of beacon nodes from their URLs.
    fn nodes(urls: &[String]) -> Result<BeaconNodes, ValidatorError> {
        let clients = urls
            .iter()
            .map(|url| BeaconClient::new(url, ClientConfig::default()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BeaconNodes::new(clients)?)
    }

    /// The chain's genesis, retried until a beacon node answers.
    async fn genesis(nodes: &BeaconNodes) -> Genesis {
        loop {
            match nodes
                .first(|client| async move { client.beacon().genesis().await })
                .await
            {
                Ok(genesis) => return genesis,
                Err(error) => {
                    warn!(%error, "waiting for a beacon node to report genesis");
                    time::sleep(GENESIS_RETRY).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Bytes32;

    use super::*;

    fn parse(arguments: &[&str]) -> Result<ValidatorCommand, CliError> {
        ValidatorCommand::parse(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    fn run(arguments: &[&str]) -> ValidatorRun {
        match parse(arguments).unwrap() {
            ValidatorCommand::Run(run) => *run,
            ValidatorCommand::Help => panic!("expected a run"),
        }
    }

    #[test]
    fn defaults_use_the_local_beacon_node() {
        let run = run(&[]);
        assert_eq!(run.beacon_nodes, [DEFAULT_BEACON_NODE]);
        assert_eq!(run.proposer_nodes, Vec::<String>::new());
        assert_eq!(run.broadcast, BTreeSet::from([ApiTopic::Subscriptions]));
        assert_eq!(run.datadir, PathBuf::from("validator"));
        assert_eq!(run.defaults.gas_limit, DEFAULT_GAS_LIMIT);
        assert_eq!(run.settings, ClientSettings::default());
        assert_eq!(run.keymanager, None);
        assert_eq!(run.metrics, None);
        assert!(!run.init_slashing_protection);
        assert_eq!(run.preset, PresetName::Mainnet);
    }

    #[test]
    fn node_and_server_flags_reach_the_run() {
        let run = run(&[
            "--network",
            "minimal",
            "--datadir",
            "vc",
            "--beacon-node",
            "http://10.0.0.1:5052,http://10.0.0.2:5052",
            "--beacon-node",
            "http://10.0.0.4:5052",
            "--proposer-nodes",
            "http://10.0.0.5:5052",
            "--broadcast",
            "attestations,blocks",
            "--remote-signer",
            "http://10.0.0.3:9000",
            "--init-slashing-protection",
            "--keymanager-address",
            "127.0.0.1:5062",
            "--http-token-path",
            "token.txt",
            "--http-allow-origin",
            "http://localhost:3000",
            "--metrics",
            "--metrics-address",
            "0.0.0.0",
            "--metrics-port",
            "9064",
            "--metrics-allow-origin",
            "*",
            "--log",
            "debug",
        ]);
        assert_eq!(run.preset, PresetName::Minimal);
        assert_eq!(run.datadir, PathBuf::from("vc"));
        assert_eq!(
            run.beacon_nodes,
            [
                "http://10.0.0.1:5052",
                "http://10.0.0.2:5052",
                "http://10.0.0.4:5052"
            ]
        );
        assert_eq!(run.proposer_nodes, ["http://10.0.0.5:5052"]);
        assert_eq!(
            run.broadcast,
            BTreeSet::from([ApiTopic::Attestations, ApiTopic::Blocks])
        );
        assert_eq!(run.remote_signer.as_deref(), Some("http://10.0.0.3:9000"));
        assert!(run.init_slashing_protection);
        assert_eq!(run.keymanager, Some("127.0.0.1:5062".parse().unwrap()));
        assert_eq!(run.token_path, Some(PathBuf::from("token.txt")));
        assert_eq!(
            run.keymanager_origin,
            Some(Cors::parse("http://localhost:3000").unwrap())
        );
        assert_eq!(run.metrics, Some("0.0.0.0:9064".parse().unwrap()));
        assert_eq!(run.metrics_origin, Some(Cors::parse("*").unwrap()));
        assert_eq!(run.log.filter, "debug");
    }

    #[test]
    fn proposal_and_duty_flags_reach_the_run() {
        let run = run(&[
            "--fee-recipient",
            "0x00000000219ab540356cbb839cbe05303d7705fa",
            "--gas-limit",
            "36000000",
            "--graffiti",
            "axiom",
            "--graffiti-append",
            "false",
            "--builder",
            "--builder-boost-factor",
            "90",
            "--builder-registration-timestamp-override",
            "1700000000",
            "--validator-registration-batch-size",
            "50",
            "--disable-attesting",
            "--distributed",
            "--doppelganger-epochs",
            "0",
        ]);
        let mut graffiti = [0; 32];
        graffiti[..5].copy_from_slice(b"axiom");
        assert_eq!(
            run.defaults,
            ProposerDefaults {
                fee_recipient: ExecutionAddress(
                    <[u8; 20]>::from_data("0x00000000219ab540356cbb839cbe05303d7705fa").unwrap()
                ),
                gas_limit: 36_000_000,
                graffiti: Graffiti(Bytes32(graffiti)),
                builder: true,
                builder_boost_factor: Some(90),
                prefer_builder_proposals: false,
            }
        );
        assert_eq!(
            run.settings,
            ClientSettings {
                doppelganger_epochs: 0,
                disable_attesting: true,
                distributed: true,
                preserve_graffiti: true,
                registration_timestamp: Some(1_700_000_000),
                registration_batch_size: 50,
                ..ClientSettings::default()
            }
        );
    }

    #[test]
    fn metrics_listen_on_localhost_5064_by_default() {
        assert_eq!(
            run(&["--metrics"]).metrics,
            Some("127.0.0.1:5064".parse().unwrap())
        );
    }

    #[test]
    fn graffiti_append_takes_an_optional_boolean() {
        // Alone, it keeps appending; with false, the graffiti is preserved as given.
        assert!(!run(&["--graffiti-append"]).settings.preserve_graffiti);
        assert!(
            !run(&["--graffiti-append", "true"])
                .settings
                .preserve_graffiti
        );
        assert!(
            run(&["--graffiti-append", "false"])
                .settings
                .preserve_graffiti
        );
        // A word that is not a boolean is the next flag.
        assert!(
            run(&["--graffiti-append", "--distributed"])
                .settings
                .distributed
        );
    }

    #[test]
    fn prefer_builder_proposals_reaches_the_defaults() {
        assert!(
            run(&["--prefer-builder-proposals"])
                .defaults
                .prefer_builder_proposals
        );
    }

    #[test]
    fn refining_flags_need_their_base_flag() {
        for (flag, value, needs) in [
            ("--metrics-address", "0.0.0.0", "--metrics"),
            ("--metrics-port", "9064", "--metrics"),
            ("--metrics-allow-origin", "*", "--metrics"),
            ("--http-token-path", "token.txt", "--keymanager-address"),
        ] {
            assert!(
                matches!(
                    parse(&[flag, value]),
                    Err(CliError::Requires { flag: given, needs: needed })
                        if given == flag && needed == needs
                ),
                "{flag}"
            );
        }
    }

    #[test]
    fn conflicting_flags_are_refused() {
        assert!(matches!(
            parse(&["--graffiti", "a", "--graffiti-file", "g.txt"]),
            Err(CliError::Conflicts {
                flag: "--graffiti",
                other: "--graffiti-file"
            })
        ));
        assert!(matches!(
            parse(&["--builder-boost-factor", "5", "--prefer-builder-proposals"]),
            Err(CliError::Conflicts {
                flag: "--builder-boost-factor",
                other: "--prefer-builder-proposals"
            })
        ));
    }

    #[test]
    fn malformed_values_are_named() {
        for (arguments, flag) in [
            (&["--graffiti", &"x".repeat(33)][..], "--graffiti"),
            (&["--broadcast", "votes"][..], "--broadcast"),
            (
                &["--validator-registration-batch-size", "0"][..],
                "--validator-registration-batch-size",
            ),
            (
                &["--http-allow-origin", "localhost:3000"][..],
                "--http-allow-origin",
            ),
        ] {
            assert!(
                matches!(parse(arguments), Err(CliError::InvalidValue { flag: named, .. }) if named == flag),
                "{flag}"
            );
        }
    }
}
