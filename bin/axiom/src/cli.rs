//! The command line: flags parsed by hand into a typed configuration.

use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use axiom_discv5::Enr;
use axiom_node::{
    AnchorSource, DiscoverySettings, EngineConfig, HistorySettings, NetworkSettings, NodeConfig,
    PortMappingSettings, SnapshotInterval, StorageMode, WeakSubjectivity,
};
use axiom_p2p::Multiaddr;
use axiom_slasher::{LayoutError, SlasherConfig};
use axiom_telemetry::{LogConfig, LogFormat};
use axiom_types::{ChainConfig, ConfigError};
use axiom_yaml::{ParseError, Yaml};
use thiserror::Error;

use crate::{
    account::Account,
    run::{PresetName, Run},
    validator::ValidatorCommand,
};

/// The usage text, shown by the help flag.
pub(crate) const USAGE: &str = "\
axiom: an Ethereum consensus client

USAGE:
    axiom [OPTIONS]
    axiom validator [OPTIONS]            run the validator client; see axiom validator --help
    axiom account <COMMAND> [OPTIONS]    keys, deposits, and slashing protection files

OPTIONS:
    --network <NAME>             mainnet or minimal [default: mainnet]
    --config <FILE>              chain config YAML; its PRESET_BASE picks the preset
    --genesis-state <FILE>       SSZ genesis state, used when the database is empty
                                 with a checkpoint, it lets an archive rebuild older states
    --checkpoint-state <FILE>    SSZ post-state of a trusted block, instead of genesis
    --checkpoint-block <FILE>    SSZ signed trusted block, with --checkpoint-state
    --checkpoint-sync-url <URL>  trusted beacon API to download the finalized checkpoint from
    --weak-subjectivity-checkpoint <ROOT:EPOCH>
                                 block root and epoch the chain must pass through
    --archive                    keep state snapshots and backfill to genesis
    --snapshot-interval <SLOTS>  slots between archive snapshots [default: 2048]
    --datadir <DIR>              database directory [default: in memory]
    --http-address <ADDR>        beacon API address [default: 127.0.0.1:5052]
    --no-http                    disable the beacon API
    --metrics-address <ADDR>     Prometheus endpoint address [default: disabled]
    --listen-address <ADDR>      libp2p TCP address [default: 0.0.0.0:9000]
    --quic-port <PORT>           libp2p QUIC UDP port [default: the libp2p port + 1]
    --no-quic                    listen and dial over TCP only
    --boot-node <MULTIADDR>      peer to dial at startup, repeatable
    --target-peers <COUNT>       peers to keep connected [default: 64]
    --nat                        map the ports on the gateway, over NAT-PMP or UPnP
    --custody-groups <COUNT>     custody groups to keep [default: the spec's requirement]
    --discovery-port <PORT>      discv5 UDP port [default: the libp2p port]
    --enr-address <IP>           public IPv4 address announced in the node record
    --boot-enr <ENR>             discovery record to bootstrap from, repeatable
    --no-discovery               find peers through boot nodes only
    --no-network                 run without peers
    --execution-endpoint <URL>   engine API endpoint, such as http://127.0.0.1:8551
    --jwt-secret <FILE>          hex JWT secret shared with the engine
    --slasher                    detect slashable votes and proposals, and pool the evidence
    --slasher-history <EPOCHS>   epochs of votes the slasher keeps [default: 4096]
    --slasher-chunk-epochs <N>   epochs per span chunk on disk [default: 16]
    --slasher-chunk-validators <N>
                                 validators per span chunk on disk [default: 1024]
    --log <FILTER>               log filter, such as info,axiom_node=debug [default: info]
    --log-format <FORMAT>        compact, pretty, or json [default: compact]
    -h, --help                   print this help
    -V, --version                print the version
";

/// Default address of the beacon API, the port every client uses.
const DEFAULT_HTTP_ADDRESS: &str = "127.0.0.1:5052";

/// Default peer count target.
///
/// A mesh wants 6 to 12 peers per topic, per the phase0 gossipsub parameters.
/// Sixty-four peers fill every topic's mesh and leave spares.
const DEFAULT_TARGET_PEERS: usize = 64;

/// Default libp2p address, the port every client uses.
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:9000";

/// Whether and where libp2p listens on QUIC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum QuicChoice {
    /// The UDP port after the libp2p TCP port.
    #[default]
    Default,
    /// A chosen UDP port.
    Port(u16),
    /// TCP only.
    Off,
}

/// What the command line asks for.
#[derive(Debug)]
pub(crate) enum Command {
    /// Print the usage text.
    Help,
    /// Print the version.
    Version,
    /// Run a node.
    Run(Box<Run>),
    /// Run an account command.
    Account(Box<Account>),
    /// Run the validator client.
    Validator(ValidatorCommand),
}

/// Why the command line cannot be used.
#[derive(Debug, Error)]
pub(crate) enum CliError {
    /// A flag this client does not know.
    #[error("unknown flag {0}")]
    UnknownFlag(String),
    /// A flag that needs a value came last.
    #[error("{0} needs a value")]
    MissingValue(&'static str),
    /// A flag's value does not parse.
    #[error("invalid value for {flag}: {value}")]
    InvalidValue {
        /// The flag.
        flag: &'static str,
        /// The value given.
        value: String,
    },
    /// A slasher setting was given without the slasher.
    #[error("{0} needs --slasher")]
    SlasherDisabled(&'static str),
    /// The slasher settings cannot lay out its history.
    #[error("slasher: {0}")]
    Slasher(#[from] LayoutError),
    /// Only one of the engine endpoint and its secret was given.
    #[error("--execution-endpoint and --jwt-secret go together")]
    IncompleteEngine,
    /// Two checkpoint sources were given, or a checkpoint file is missing.
    #[error(
        "give --genesis-state, both --checkpoint-state and --checkpoint-block, or --checkpoint-sync-url"
    )]
    ConflictingAnchors,
    /// The config file cannot be read.
    #[error("cannot read the config file {}: {source}", .path.display())]
    ConfigFile {
        /// The config file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The config file is not valid YAML.
    #[error("config file {} is not YAML: {source}", .path.display())]
    ConfigYaml {
        /// The config file.
        path: PathBuf,
        /// Where and why the parser stopped.
        #[source]
        source: ParseError,
    },
    /// The config file has a bad value.
    #[error("config file {}: {source}", .path.display())]
    Config {
        /// The config file.
        path: PathBuf,
        /// The key and the value that is wrong.
        #[source]
        source: ConfigError,
    },
}

/// The flags as given, before they are resolved into a configuration.
#[derive(Debug, Default)]
pub(crate) struct Cli {
    /// The network name.
    network: Option<String>,
    /// The config file.
    config: Option<PathBuf>,
    /// The genesis state file.
    genesis_state: Option<PathBuf>,
    /// The checkpoint state file.
    checkpoint_state: Option<PathBuf>,
    /// The checkpoint block file.
    checkpoint_block: Option<PathBuf>,
    /// The beacon API to download a checkpoint from.
    checkpoint_sync_url: Option<String>,
    /// The checkpoint the chain must pass through.
    weak_subjectivity: Option<WeakSubjectivity>,
    /// Slots between archive snapshots, given only in archive mode.
    snapshot_interval: Option<SnapshotInterval>,
    /// The database directory.
    datadir: Option<PathBuf>,
    /// The beacon API address.
    http_address: Option<SocketAddr>,
    /// Whether the beacon API is off.
    no_http: bool,
    /// The metrics address.
    metrics_address: Option<SocketAddr>,
    /// The libp2p address.
    listen_address: Option<SocketAddr>,
    /// The libp2p QUIC choice.
    quic: QuicChoice,
    /// Peers to dial at startup.
    boot_nodes: Vec<Multiaddr>,
    /// Peers to keep connected.
    target_peers: Option<usize>,
    /// Gateway port mapping.
    port_mapping: PortMappingSettings,
    /// Custody groups to keep.
    custody_groups: Option<u64>,
    /// Whether the network is off.
    no_network: bool,
    /// The discovery UDP port.
    discovery_port: Option<u16>,
    /// The address announced in the node record.
    enr_address: Option<Ipv4Addr>,
    /// Discovery records to bootstrap from.
    boot_enrs: Vec<Enr>,
    /// Whether discovery is off.
    no_discovery: bool,
    /// The engine endpoint.
    execution_endpoint: Option<String>,
    /// The engine secret file.
    jwt_secret: Option<PathBuf>,
    /// The log filter.
    log: Option<String>,
    /// The log format.
    log_format: Option<LogFormat>,
    /// The slasher flags.
    slasher: SlasherFlags,
}

/// The slasher flags as given.
#[derive(Debug, Default)]
struct SlasherFlags {
    /// Whether the slasher runs.
    enabled: bool,
    /// Epochs of history.
    history: Option<u64>,
    /// Epochs per span chunk.
    chunk_epochs: Option<u64>,
    /// Validators per span chunk.
    chunk_validators: Option<u64>,
}

impl SlasherFlags {
    /// The settings with defaults filled in, or none when the slasher is off.
    fn resolve(&self) -> Result<Option<SlasherConfig>, CliError> {
        if !self.enabled {
            let settings = [
                ("--slasher-history", self.history),
                ("--slasher-chunk-epochs", self.chunk_epochs),
                ("--slasher-chunk-validators", self.chunk_validators),
            ];
            return match settings.iter().find(|(_, value)| value.is_some()) {
                Some((flag, _)) => Err(CliError::SlasherDisabled(flag)),
                None => Ok(None),
            };
        }
        let defaults = SlasherConfig::default();
        let config = SlasherConfig {
            history_length: self.history.unwrap_or(defaults.history_length),
            chunk_size: self.chunk_epochs.unwrap_or(defaults.chunk_size),
            validator_chunk_size: self
                .chunk_validators
                .unwrap_or(defaults.validator_chunk_size),
            ..defaults
        };
        // The layout is checked now, so a bad flag fails before the node starts.
        config.geometry()?;
        Ok(Some(config))
    }
}

impl Cli {
    /// Parses arguments, without the program name.
    ///
    /// # Errors
    ///
    /// Fails on an unknown flag, a missing value, or a value that does not parse.
    pub(crate) fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Command, CliError> {
        let mut arguments = arguments.into_iter().peekable();
        // A leading command word picks a subcommand; flags alone run the beacon node.
        if arguments.next_if(|word| word == "account").is_some() {
            return Account::parse(arguments).map(|account| Command::Account(Box::new(account)));
        }
        if arguments.next_if(|word| word == "validator").is_some() {
            return ValidatorCommand::parse(arguments).map(Command::Validator);
        }
        Self::parse_node(arguments)
    }

    /// Parses the beacon node's flags.
    fn parse_node(mut arguments: impl Iterator<Item = String>) -> Result<Command, CliError> {
        let mut cli = Self::default();
        while let Some(flag) = arguments.next() {
            // Each flag either stands alone or takes the next argument as its value.
            let mut value =
                |name: &'static str| arguments.next().ok_or(CliError::MissingValue(name));
            match flag.as_str() {
                "-h" | "--help" => return Ok(Command::Help),
                "-V" | "--version" => return Ok(Command::Version),
                "--network" => cli.network = Some(value("--network")?),
                "--config" => cli.config = Some(value("--config")?.into()),
                "--genesis-state" => cli.genesis_state = Some(value("--genesis-state")?.into()),
                "--checkpoint-state" => {
                    cli.checkpoint_state = Some(value("--checkpoint-state")?.into());
                }
                "--checkpoint-block" => {
                    cli.checkpoint_block = Some(value("--checkpoint-block")?.into());
                }
                "--checkpoint-sync-url" => {
                    cli.checkpoint_sync_url = Some(value("--checkpoint-sync-url")?);
                }
                "--weak-subjectivity-checkpoint" => {
                    let text = value("--weak-subjectivity-checkpoint")?;
                    cli.weak_subjectivity =
                        Some(Self::parsed("--weak-subjectivity-checkpoint", text)?);
                }
                "--archive" => {
                    cli.snapshot_interval
                        .get_or_insert(SnapshotInterval::DEFAULT);
                }
                "--snapshot-interval" => {
                    let text = value("--snapshot-interval")?;
                    cli.snapshot_interval = Some(Self::parsed("--snapshot-interval", text)?);
                }
                "--datadir" => cli.datadir = Some(value("--datadir")?.into()),
                "--http-address" => {
                    cli.http_address =
                        Some(Self::parsed("--http-address", value("--http-address")?)?);
                }
                "--no-http" => cli.no_http = true,
                "--metrics-address" => {
                    cli.metrics_address = Some(Self::parsed(
                        "--metrics-address",
                        value("--metrics-address")?,
                    )?);
                }
                "--execution-endpoint" => {
                    cli.execution_endpoint = Some(value("--execution-endpoint")?);
                }
                "--jwt-secret" => cli.jwt_secret = Some(value("--jwt-secret")?.into()),
                "--slasher" => cli.slasher.enabled = true,
                "--slasher-history" => {
                    let text = value("--slasher-history")?;
                    cli.slasher.history = Some(Self::parsed("--slasher-history", text)?);
                }
                "--slasher-chunk-epochs" => {
                    let text = value("--slasher-chunk-epochs")?;
                    cli.slasher.chunk_epochs = Some(Self::parsed("--slasher-chunk-epochs", text)?);
                }
                "--slasher-chunk-validators" => {
                    let text = value("--slasher-chunk-validators")?;
                    cli.slasher.chunk_validators =
                        Some(Self::parsed("--slasher-chunk-validators", text)?);
                }
                "--log" => cli.log = Some(value("--log")?),
                "--log-format" => {
                    cli.log_format = Some(Self::log_format(value("--log-format")?)?);
                }
                _ => {
                    if !cli.network_flag(&flag, &mut value)? {
                        return Err(CliError::UnknownFlag(flag));
                    }
                }
            }
        }
        cli.resolve().map(|run| Command::Run(Box::new(run)))
    }

    /// Applies a networking flag, returning false when the flag is not one.
    fn network_flag(
        &mut self,
        flag: &str,
        value: &mut impl FnMut(&'static str) -> Result<String, CliError>,
    ) -> Result<bool, CliError> {
        match flag {
            "--listen-address" => {
                self.listen_address = Some(Self::parsed(
                    "--listen-address",
                    value("--listen-address")?,
                )?);
            }
            "--quic-port" => {
                let text = value("--quic-port")?;
                self.quic = QuicChoice::Port(Self::parsed("--quic-port", text)?);
            }
            "--no-quic" => self.quic = QuicChoice::Off,
            "--target-peers" => {
                let text = value("--target-peers")?;
                self.target_peers = Some(Self::parsed("--target-peers", text)?);
            }
            "--nat" => self.port_mapping.enabled = true,
            "--boot-node" => {
                let text = value("--boot-node")?;
                self.boot_nodes.push(Self::parsed("--boot-node", text)?);
            }
            "--custody-groups" => {
                let text = value("--custody-groups")?;
                self.custody_groups = Some(Self::parsed("--custody-groups", text)?);
            }
            "--no-network" => self.no_network = true,
            "--discovery-port" => {
                let text = value("--discovery-port")?;
                self.discovery_port = Some(Self::parsed("--discovery-port", text)?);
            }
            "--enr-address" => {
                let text = value("--enr-address")?;
                self.enr_address = Some(Self::parsed("--enr-address", text)?);
            }
            "--boot-enr" => {
                let text = value("--boot-enr")?;
                self.boot_enrs.push(Self::parsed("--boot-enr", text)?);
            }
            "--no-discovery" => self.no_discovery = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Turns the flags into a run, reading the config file if one is named.
    fn resolve(self) -> Result<Run, CliError> {
        let slasher = self.slasher.resolve()?;
        let (preset, chain) = self.chain()?;
        let engine = match (self.execution_endpoint, self.jwt_secret) {
            (Some(url), Some(jwt_secret)) => Some(EngineConfig { url, jwt_secret }),
            (None, None) => None,
            _ => return Err(CliError::IncompleteEngine),
        };
        let network = if self.no_network {
            None
        } else {
            let listen_address = self
                .listen_address
                .unwrap_or_else(|| Self::default_address(DEFAULT_LISTEN_ADDRESS));
            // Discovery shares the libp2p port number by default, over UDP.
            let discovery = (!self.no_discovery).then(|| DiscoverySettings {
                udp_port: self.discovery_port.unwrap_or_else(|| listen_address.port()),
                enr_address: self.enr_address,
                boot_enrs: self.boot_enrs,
            });
            // QUIC takes the next UDP port by default, since discovery holds the libp2p one.
            let quic_port = match self.quic {
                QuicChoice::Default => Some(listen_address.port().wrapping_add(1)),
                QuicChoice::Port(port) => Some(port),
                QuicChoice::Off => None,
            };
            Some(NetworkSettings {
                listen_address,
                quic_port,
                boot_nodes: self.boot_nodes,
                target_peers: self.target_peers.unwrap_or(DEFAULT_TARGET_PEERS),
                port_mapping: self.port_mapping,
                discovery,
                // Every node keeps at least the spec's minimum.
                custody_group_count: self
                    .custody_groups
                    .unwrap_or(chain.custody_requirement)
                    .max(chain.custody_requirement),
            })
        };
        // A checkpoint comes from both its files or from a server, and replaces genesis.
        // A genesis state given with a checkpoint seeds an archive's rebuild instead.
        let (anchor, genesis) = match (
            self.genesis_state,
            self.checkpoint_state,
            self.checkpoint_block,
            self.checkpoint_sync_url,
        ) {
            (None, None, None, None) => (None, None),
            (Some(genesis), None, None, None) => (Some(AnchorSource::Genesis(genesis)), None),
            (genesis, Some(state), Some(block), None) => {
                (Some(AnchorSource::Checkpoint { state, block }), genesis)
            }
            (genesis, None, None, Some(url)) => (Some(AnchorSource::Url(url)), genesis),
            _ => return Err(CliError::ConflictingAnchors),
        };
        // An interval implies the archive mode it paces.
        let mode = self
            .snapshot_interval
            .map_or(StorageMode::Pruned, StorageMode::Archive);
        let http_address = if self.no_http {
            None
        } else {
            Some(
                self.http_address
                    .unwrap_or_else(|| Self::default_address(DEFAULT_HTTP_ADDRESS)),
            )
        };
        Ok(Run {
            preset,
            chain,
            node: NodeConfig {
                data_dir: self.datadir,
                anchor,
                http_address,
                metrics_address: self.metrics_address,
                engine,
                network,
                slasher,
                history: HistorySettings {
                    mode,
                    weak_subjectivity: self.weak_subjectivity,
                    genesis,
                },
                ..NodeConfig::default()
            },
            log: LogConfig {
                filter: self.log.unwrap_or_else(|| "info".to_owned()),
                format: self.log_format.unwrap_or_default(),
            },
        })
    }

    /// The preset and chain configuration, from the config file or the network name.
    fn chain(&self) -> Result<(PresetName, ChainConfig), CliError> {
        Self::choose_chain(self.network.as_deref(), self.config.as_deref())
    }

    /// The preset and chain configuration a network name or a config file names.
    ///
    /// A config file wins over the network name.
    pub(crate) fn choose_chain(
        network: Option<&str>,
        config: Option<&Path>,
    ) -> Result<(PresetName, ChainConfig), CliError> {
        if let Some(path) = config {
            let text = fs::read_to_string(path).map_err(|source| CliError::ConfigFile {
                path: path.to_owned(),
                source,
            })?;
            let yaml = Yaml::parse(&text).map_err(|source| CliError::ConfigYaml {
                path: path.to_owned(),
                source,
            })?;
            // The file's own preset base wins over the network flag.
            let preset = match yaml.get("PRESET_BASE").and_then(Yaml::as_str) {
                Some("minimal") => PresetName::Minimal,
                _ => PresetName::Mainnet,
            };
            let chain = ChainConfig::from_yaml(&yaml).map_err(|source| CliError::Config {
                path: path.to_owned(),
                source,
            })?;
            return Ok((preset, chain));
        }
        match network {
            None | Some("mainnet") => Ok((PresetName::Mainnet, ChainConfig::mainnet())),
            Some("minimal") => Ok((PresetName::Minimal, ChainConfig::minimal())),
            Some(other) => Err(CliError::InvalidValue {
                flag: "--network",
                value: other.to_owned(),
            }),
        }
    }

    /// Any flag whose value parses from text.
    fn parsed<T: FromStr>(flag: &'static str, value: String) -> Result<T, CliError> {
        value
            .parse()
            .map_err(|_| CliError::InvalidValue { flag, value })
    }

    /// The log format flag.
    pub(crate) fn log_format(value: String) -> Result<LogFormat, CliError> {
        match value.as_str() {
            "compact" => Ok(LogFormat::Compact),
            "pretty" => Ok(LogFormat::Pretty),
            "json" => Ok(LogFormat::Json),
            _ => Err(CliError::InvalidValue {
                flag: "--log-format",
                value,
            }),
        }
    }

    /// A default address from its literal.
    fn default_address(literal: &str) -> SocketAddr {
        // Invariant: every default is a literal IPv4 socket address, so it always parses.
        literal
            .parse()
            .expect("default addresses are valid literals")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example record of EIP-778.
    const EIP_778_RECORD: &str = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    fn parse(arguments: &[&str]) -> Result<Command, CliError> {
        Cli::parse(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    fn run(arguments: &[&str]) -> Run {
        match parse(arguments).unwrap() {
            Command::Run(run) => *run,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    #[test]
    fn no_flags_run_mainnet_in_memory_with_the_api_on() {
        let run = run(&[]);

        assert_eq!(run.preset, PresetName::Mainnet);
        assert_eq!(run.chain, ChainConfig::mainnet());
        assert_eq!(
            run.node,
            NodeConfig {
                http_address: Some("127.0.0.1:5052".parse().unwrap()),
                network: Some(NetworkSettings {
                    listen_address: "0.0.0.0:9000".parse().unwrap(),
                    quic_port: Some(9001),
                    boot_nodes: Vec::new(),
                    target_peers: 64,
                    port_mapping: PortMappingSettings::default(),
                    custody_group_count: 4,
                    discovery: Some(DiscoverySettings {
                        udp_port: 9000,
                        enr_address: None,
                        boot_enrs: Vec::new(),
                    }),
                }),
                ..NodeConfig::default()
            }
        );
        assert_eq!(run.log.filter, "info");
        assert_eq!(run.log.format, LogFormat::Compact);
    }

    #[test]
    fn every_flag_reaches_the_configuration() {
        let run = run(&[
            "--network",
            "minimal",
            "--genesis-state",
            "genesis.ssz",
            "--datadir",
            "data",
            "--no-http",
            "--metrics-address",
            "0.0.0.0:5054",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--jwt-secret",
            "jwt.hex",
            "--log",
            "debug",
            "--log-format",
            "json",
            "--listen-address",
            "127.0.0.1:9001",
            "--quic-port",
            "9101",
            "--target-peers",
            "32",
            "--nat",
            "--boot-node",
            "/ip4/10.0.0.1/tcp/9000",
            "--custody-groups",
            "128",
            "--discovery-port",
            "9002",
            "--enr-address",
            "203.0.113.7",
            "--boot-enr",
            EIP_778_RECORD,
        ]);

        assert_eq!(run.preset, PresetName::Minimal);
        assert_eq!(run.chain, ChainConfig::minimal());
        assert_eq!(
            run.node,
            NodeConfig {
                data_dir: Some("data".into()),
                anchor: Some(AnchorSource::Genesis("genesis.ssz".into())),
                http_address: None,
                metrics_address: Some("0.0.0.0:5054".parse().unwrap()),
                engine: Some(EngineConfig {
                    url: "http://127.0.0.1:8551".to_owned(),
                    jwt_secret: "jwt.hex".into(),
                }),
                network: Some(NetworkSettings {
                    listen_address: "127.0.0.1:9001".parse().unwrap(),
                    quic_port: Some(9101),
                    boot_nodes: vec!["/ip4/10.0.0.1/tcp/9000".parse().unwrap()],
                    target_peers: 32,
                    port_mapping: PortMappingSettings { enabled: true },
                    custody_group_count: 128,
                    discovery: Some(DiscoverySettings {
                        udp_port: 9002,
                        enr_address: Some(Ipv4Addr::new(203, 0, 113, 7)),
                        boot_enrs: vec![EIP_778_RECORD.parse().unwrap()],
                    }),
                }),
                ..NodeConfig::default()
            }
        );
        assert_eq!(run.log.filter, "debug");
        assert_eq!(run.log.format, LogFormat::Json);
    }

    #[test]
    fn the_slasher_flags_set_its_layout() {
        // History of 1024 epochs in chunks of 8 by 512 validators.
        let tuned = run(&[
            "--slasher",
            "--slasher-history",
            "1024",
            "--slasher-chunk-epochs",
            "8",
            "--slasher-chunk-validators",
            "512",
        ]);
        assert_eq!(
            tuned.node.slasher,
            Some(SlasherConfig {
                history_length: 1024,
                chunk_size: 8,
                validator_chunk_size: 512,
                ..SlasherConfig::default()
            })
        );
        // The bare flag takes every default.
        assert_eq!(
            run(&["--slasher"]).node.slasher,
            Some(SlasherConfig::default())
        );
    }

    #[test]
    fn slasher_settings_need_the_slasher_and_a_valid_layout() {
        assert!(matches!(
            parse(&["--slasher-history", "64"]),
            Err(CliError::SlasherDisabled("--slasher-history"))
        ));
        // 100 epochs do not split into chunks of 16.
        assert!(matches!(
            parse(&["--slasher", "--slasher-history", "100"]),
            Err(CliError::Slasher(LayoutError::Indivisible {
                history: 100,
                chunk: 16
            }))
        ));
    }

    #[test]
    fn history_flags_reach_the_configuration() {
        // A checkpoint from a server, archived every 64 slots, with genesis for the rebuild.
        let root = "0x8584188b86a9296932785cc2827b925f9deebacce6d72ad8d53171fa046b43d9";
        let checkpoint = format!("{root}:9544");
        let served = run(&[
            "--checkpoint-sync-url",
            "http://10.0.0.2:5052",
            "--genesis-state",
            "genesis.ssz",
            "--snapshot-interval",
            "64",
            "--weak-subjectivity-checkpoint",
            &checkpoint,
        ]);

        assert_eq!(
            served.node.anchor,
            Some(AnchorSource::Url("http://10.0.0.2:5052".to_owned()))
        );
        assert_eq!(
            served.node.history,
            HistorySettings {
                mode: StorageMode::Archive(SnapshotInterval::new(64).unwrap()),
                weak_subjectivity: Some(checkpoint.parse().unwrap()),
                genesis: Some("genesis.ssz".into()),
            }
        );

        // The archive flag alone takes the default interval; checkpoint files keep genesis too.
        let files = run(&[
            "--archive",
            "--genesis-state",
            "g.ssz",
            "--checkpoint-state",
            "s.ssz",
            "--checkpoint-block",
            "b.ssz",
        ]);
        assert_eq!(
            files.node.history.mode,
            StorageMode::Archive(SnapshotInterval::DEFAULT)
        );
        assert_eq!(files.node.history.genesis, Some("g.ssz".into()));
        assert_eq!(
            files.node.anchor,
            Some(AnchorSource::Checkpoint {
                state: "s.ssz".into(),
                block: "b.ssz".into(),
            })
        );
    }

    #[test]
    fn help_and_version_stop_parsing() {
        // A help flag wins even when a bad flag follows it.
        assert!(matches!(parse(&["--help", "--bogus"]), Ok(Command::Help)));
        assert!(matches!(parse(&["-V"]), Ok(Command::Version)));
    }

    #[test]
    fn malformed_command_lines_are_refused() {
        assert!(
            matches!(parse(&["--bogus"]), Err(CliError::UnknownFlag(flag)) if flag == "--bogus")
        );
        assert!(matches!(
            parse(&["--datadir"]),
            Err(CliError::MissingValue("--datadir"))
        ));
        assert!(matches!(
            parse(&["--network", "holesky"]),
            Err(CliError::InvalidValue {
                flag: "--network",
                ..
            })
        ));
        assert!(matches!(
            parse(&["--http-address", "localhost"]),
            Err(CliError::InvalidValue {
                flag: "--http-address",
                ..
            })
        ));
        assert!(matches!(
            parse(&["--boot-enr", "enr:not-base64!"]),
            Err(CliError::InvalidValue {
                flag: "--boot-enr",
                ..
            })
        ));
        assert!(matches!(
            parse(&["--boot-node", "not-a-multiaddr"]),
            Err(CliError::InvalidValue {
                flag: "--boot-node",
                ..
            })
        ));
        // A checkpoint needs both files, and excludes a genesis state.
        assert!(matches!(
            parse(&["--checkpoint-state", "state.ssz"]),
            Err(CliError::ConflictingAnchors)
        ));
        assert!(matches!(
            parse(&[
                "--checkpoint-sync-url",
                "http://127.0.0.1:5052",
                "--checkpoint-state",
                "s.ssz",
                "--checkpoint-block",
                "b.ssz"
            ]),
            Err(CliError::ConflictingAnchors)
        ));
        assert!(matches!(
            parse(&["--weak-subjectivity-checkpoint", "0x12:3"]),
            Err(CliError::InvalidValue {
                flag: "--weak-subjectivity-checkpoint",
                ..
            })
        ));
        assert!(matches!(
            parse(&["--snapshot-interval", "0"]),
            Err(CliError::InvalidValue {
                flag: "--snapshot-interval",
                ..
            })
        ));
        // An engine needs both its endpoint and its secret.
        assert!(matches!(
            parse(&["--execution-endpoint", "http://127.0.0.1:8551"]),
            Err(CliError::IncompleteEngine)
        ));
    }
}
