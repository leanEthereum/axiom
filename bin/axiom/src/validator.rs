//! The validator command: keys from a directory, duties through beacon nodes, until a signal.

use std::{
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use axiom_beacon_json::api::Genesis;
use axiom_http::{Client, ClientConfig, Endpoint, HttpError};
use axiom_json::Data;
use axiom_node::SystemClock;
use axiom_telemetry::{LogConfig, LogFormat};
use axiom_types::{
    Bytes32, ChainConfig, ExecutionAddress, Mainnet, Minimal, Preset, SlotClock, Version,
};
use axiom_validator::{
    beacon::{BeaconClient, BeaconError, BeaconNodes},
    duties::{ClientSettings, DutyContext, SlotTimer, ValidatorClient},
    keymanager::{DirectoryError, KeyDirectory, Keymanager},
    protection::{ProtectionError, SlashingDatabase},
    signing::{
        RemoteError, RemoteSigner, SignError, SigningContext, SigningGuard, ValidatorSigner,
    },
    validators::{DEFAULT_GAS_LIMIT, ProposerDefaults, ValidatorStore},
};
use thiserror::Error;
use tokio::{runtime::Builder, task, time};
use tracing::{info, warn};

use crate::{
    cli::{Cli, CliError},
    run::{PresetName, Run},
};

/// The usage text of the validator command.
pub(crate) const VALIDATOR_USAGE: &str = "\
axiom validator: perform duties for the keys in a directory

USAGE:
    axiom validator [OPTIONS]

OPTIONS:
    --network <NAME>               mainnet or minimal [default: mainnet]
    --config <FILE>                chain config YAML; its PRESET_BASE picks the preset
    --datadir <DIR>                keys, secrets, and slashing protection [default: validator]
    --beacon-node <URL>            beacon API endpoint, repeatable, in order of preference
                                   [default: http://127.0.0.1:5052]
    --remote-signer <URL>          also sign with every key a remote signer holds
    --fee-recipient <ADDR>         default fee recipient [default: the zero address]
    --gas-limit <GAS>              default gas limit [default: 60000000]
    --graffiti <TEXT>              default graffiti, up to 32 bytes
    --builder                      register with external builders
    --builder-boost-factor <N>     boost factor sent with block requests
    --doppelganger-epochs <N>      epochs new keys wait before signing [default: 2]
    --keymanager-address <ADDR>    serve the keymanager API, token in DIR/api-token.txt
    --log <FILTER>                 log filter [default: info]
    --log-format <FORMAT>          compact, pretty, or json [default: compact]
    -h, --help                     print this help
";

/// Default beacon node, the beacon API's usual address.
const DEFAULT_BEACON_NODE: &str = "http://127.0.0.1:5052";

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
    /// A remote signer whose keys are used too.
    remote_signer: Option<String>,
    /// Proposal defaults.
    defaults: ProposerDefaults,
    /// Client behaviour.
    settings: ClientSettings,
    /// Where the keymanager API listens, if anywhere.
    keymanager: Option<SocketAddr>,
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
    /// The key directory cannot load.
    #[error("keys: {0}")]
    Directory(#[from] DirectoryError),
    /// A key cannot be added.
    #[error("key: {0}")]
    Sign(#[from] SignError),
    /// The remote signer cannot list its keys.
    #[error("remote signer: {0}")]
    Remote(#[from] RemoteError),
}

impl ValidatorCommand {
    /// Parses the flags after the word validator.
    ///
    /// # Errors
    ///
    /// Fails on an unknown flag, a missing value, or a value that does not parse.
    pub(crate) fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
        let mut network = None;
        let mut config: Option<PathBuf> = None;
        let mut datadir = PathBuf::from("validator");
        let mut beacon_nodes = Vec::new();
        let mut remote_signer = None;
        let mut defaults = ProposerDefaults {
            gas_limit: DEFAULT_GAS_LIMIT,
            ..ProposerDefaults::default()
        };
        let mut settings = ClientSettings::default();
        let mut keymanager = None;
        let mut log = LogConfig {
            filter: "info".to_owned(),
            format: LogFormat::default(),
        };
        let mut arguments = arguments.into_iter();
        while let Some(flag) = arguments.next() {
            let mut value =
                |name: &'static str| arguments.next().ok_or(CliError::MissingValue(name));
            match flag.as_str() {
                "-h" | "--help" => return Ok(Self::Help),
                "--network" => network = Some(value("--network")?),
                "--config" => config = Some(value("--config")?.into()),
                "--datadir" => datadir = value("--datadir")?.into(),
                "--beacon-node" => beacon_nodes.push(value("--beacon-node")?),
                "--remote-signer" => remote_signer = Some(value("--remote-signer")?),
                "--fee-recipient" => {
                    let text = value("--fee-recipient")?;
                    let bytes =
                        <[u8; 20]>::from_data(&text).map_err(|_| CliError::InvalidValue {
                            flag: "--fee-recipient",
                            value: text,
                        })?;
                    defaults.fee_recipient = ExecutionAddress(bytes);
                }
                "--gas-limit" => {
                    defaults.gas_limit = Self::parsed("--gas-limit", value("--gas-limit")?)?;
                }
                "--graffiti" => defaults.graffiti = Self::graffiti(value("--graffiti")?)?,
                "--builder" => defaults.builder = true,
                "--builder-boost-factor" => {
                    let text = value("--builder-boost-factor")?;
                    settings.builder_boost_factor =
                        Some(Self::parsed("--builder-boost-factor", text)?);
                }
                "--doppelganger-epochs" => {
                    let text = value("--doppelganger-epochs")?;
                    settings.doppelganger_epochs = Self::parsed("--doppelganger-epochs", text)?;
                }
                "--keymanager-address" => {
                    let text = value("--keymanager-address")?;
                    keymanager = Some(Self::parsed("--keymanager-address", text)?);
                }
                "--log" => log.filter = value("--log")?,
                "--log-format" => log.format = Cli::log_format(value("--log-format")?)?,
                _ => return Err(CliError::UnknownFlag(flag)),
            }
        }
        if beacon_nodes.is_empty() {
            beacon_nodes.push(DEFAULT_BEACON_NODE.to_owned());
        }
        let (preset, chain) = Cli::choose_chain(network.as_deref(), config.as_deref())?;
        Ok(Self::Run(Box::new(ValidatorRun {
            preset,
            chain,
            datadir,
            beacon_nodes,
            remote_signer,
            defaults,
            settings,
            keymanager,
            log,
        })))
    }

    /// Any flag whose value parses from text.
    fn parsed<T: FromStr>(flag: &'static str, value: String) -> Result<T, CliError> {
        value
            .parse()
            .map_err(|_| CliError::InvalidValue { flag, value })
    }

    /// Graffiti text, zero-padded to 32 bytes.
    fn graffiti(text: String) -> Result<Bytes32, CliError> {
        let bytes = text.as_bytes();
        if bytes.len() > 32 {
            return Err(CliError::InvalidValue {
                flag: "--graffiti",
                value: text,
            });
        }
        let mut graffiti = [0; 32];
        graffiti[..bytes.len()].copy_from_slice(bytes);
        Ok(Bytes32(graffiti))
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
            }
        })
    }

    /// Wires the client together and runs it.
    async fn run<P: Preset>(self) -> Result<(), ValidatorError> {
        let clients = self
            .beacon_nodes
            .iter()
            .map(|url| BeaconClient::new(url, ClientConfig::default()))
            .collect::<Result<Vec<_>, _>>()?;
        let nodes = Arc::new(BeaconNodes::new(clients)?);
        let genesis = Self::genesis(&nodes).await;
        if genesis.genesis_fork_version != self.chain.genesis_fork_version {
            return Err(ValidatorError::WrongChain {
                node: genesis.genesis_fork_version,
                config: self.chain.genesis_fork_version,
            });
        }

        // Slashing protection and keys, both under the data directory.
        let directory = Arc::new(KeyDirectory::open(&self.datadir)?);
        let protection = Arc::new(SlashingDatabase::open(
            &self.datadir.join("slashing_protection"),
            genesis.genesis_validators_root,
        )?);
        let config = Arc::new(self.chain);
        let context = SigningContext::new(Arc::clone(&config), genesis.genesis_validators_root);
        let store = Arc::new(ValidatorStore::new(
            SigningGuard::new(context, protection),
            self.defaults,
        ));
        let doppelganger = self.settings.doppelganger_epochs > 0;
        for key in directory.load()? {
            store.add(key.signer, !doppelganger)?;
        }
        if let Some(url) = &self.remote_signer {
            let client = Arc::new(Client::new(Endpoint::parse(url)?, ClientConfig::default()));
            for pubkey in RemoteSigner::public_keys(&client).await? {
                let signer = RemoteSigner::new(Arc::clone(&client), pubkey);
                store.add(ValidatorSigner::Remote(signer), !doppelganger)?;
            }
        }
        info!(
            keys = store.pubkeys().len(),
            doppelganger, "validator keys loaded"
        );

        let slots = SlotClock::new(genesis.genesis_time * 1000, config.slot_duration_ms.max(1));
        let timer = SlotTimer::new(Arc::new(SystemClock), slots);
        let keymanager = match self.keymanager {
            Some(address) => {
                let token = directory.api_token()?;
                let server = Keymanager::<P>::new(
                    Arc::clone(&store),
                    Arc::clone(&directory),
                    &token,
                    timer.clone(),
                    doppelganger,
                )
                .bind(address)
                .await?;
                info!(%address, "keymanager API listening");
                Some(task::spawn(server.serve(Run::shutdown_signal())))
            }
            None => None,
        };
        let context = DutyContext::<P>::new(store, nodes, config, timer, self.settings);
        ValidatorClient::new(context)
            .run(Run::shutdown_signal())
            .await;
        if let Some(keymanager) = keymanager {
            keymanager.abort();
            let _aborted = keymanager.await;
        }
        Ok(())
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
        assert_eq!(run.datadir, PathBuf::from("validator"));
        assert_eq!(run.defaults.gas_limit, DEFAULT_GAS_LIMIT);
        assert_eq!(run.settings, ClientSettings::default());
        assert_eq!(run.keymanager, None);
        assert_eq!(run.preset, PresetName::Mainnet);
    }

    #[test]
    fn every_flag_reaches_the_run() {
        let run = run(&[
            "--network",
            "minimal",
            "--datadir",
            "vc",
            "--beacon-node",
            "http://10.0.0.1:5052",
            "--beacon-node",
            "http://10.0.0.2:5052",
            "--remote-signer",
            "http://10.0.0.3:9000",
            "--fee-recipient",
            "0x00000000219ab540356cbb839cbe05303d7705fa",
            "--gas-limit",
            "36000000",
            "--graffiti",
            "axiom",
            "--builder",
            "--builder-boost-factor",
            "90",
            "--doppelganger-epochs",
            "0",
            "--keymanager-address",
            "127.0.0.1:5062",
            "--log",
            "debug",
        ]);
        assert_eq!(run.preset, PresetName::Minimal);
        assert_eq!(run.datadir, PathBuf::from("vc"));
        assert_eq!(
            run.beacon_nodes,
            ["http://10.0.0.1:5052", "http://10.0.0.2:5052"]
        );
        assert_eq!(run.remote_signer.as_deref(), Some("http://10.0.0.3:9000"));
        let mut graffiti = [0; 32];
        graffiti[..5].copy_from_slice(b"axiom");
        assert_eq!(
            run.defaults,
            ProposerDefaults {
                fee_recipient: ExecutionAddress(
                    <[u8; 20]>::from_data("0x00000000219ab540356cbb839cbe05303d7705fa").unwrap()
                ),
                gas_limit: 36_000_000,
                graffiti: Bytes32(graffiti),
                builder: true,
            }
        );
        assert_eq!(
            run.settings,
            ClientSettings {
                builder_boost_factor: Some(90),
                doppelganger_epochs: 0,
                ..ClientSettings::default()
            }
        );
        assert_eq!(run.keymanager, Some("127.0.0.1:5062".parse().unwrap()));
        assert_eq!(run.log.filter, "debug");
    }

    #[test]
    fn graffiti_longer_than_32_bytes_is_refused() {
        assert!(matches!(
            parse(&["--graffiti", &"x".repeat(33)]),
            Err(CliError::InvalidValue {
                flag: "--graffiti",
                ..
            })
        ));
    }
}
