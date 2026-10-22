//! The command line: flags parsed by hand into a typed configuration.

use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use axiom_discv5::Enr;
use axiom_node::{AnchorSource, DiscoverySettings, EngineConfig, NetworkSettings, NodeConfig};
use axiom_p2p::Multiaddr;
use axiom_telemetry::{LogConfig, LogFormat};
use axiom_types::{ChainConfig, ConfigError};
use axiom_yaml::{ParseError, Yaml};
use thiserror::Error;

use crate::run::{PresetName, Run};

/// The usage text, shown by the help flag.
pub(crate) const USAGE: &str = "\
axiom: an Ethereum consensus client

USAGE:
    axiom [OPTIONS]

OPTIONS:
    --network <NAME>             mainnet or minimal [default: mainnet]
    --config <FILE>              chain config YAML; its PRESET_BASE picks the preset
    --genesis-state <FILE>       SSZ genesis state, used when the database is empty
    --checkpoint-state <FILE>    SSZ post-state of a trusted block, instead of genesis
    --checkpoint-block <FILE>    SSZ signed trusted block, with --checkpoint-state
    --datadir <DIR>              database directory [default: in memory]
    --http-address <ADDR>        beacon API address [default: 127.0.0.1:5052]
    --no-http                    disable the beacon API
    --metrics-address <ADDR>     Prometheus endpoint address [default: disabled]
    --listen-address <ADDR>      libp2p TCP address [default: 0.0.0.0:9000]
    --boot-node <MULTIADDR>      peer to dial at startup, repeatable
    --custody-groups <COUNT>     custody groups to keep [default: the spec's requirement]
    --discovery-port <PORT>      discv5 UDP port [default: the libp2p port]
    --enr-address <IP>           public IPv4 address announced in the node record
    --boot-enr <ENR>             discovery record to bootstrap from, repeatable
    --no-discovery               find peers through boot nodes only
    --no-network                 run without peers
    --execution-endpoint <URL>   engine API endpoint, such as http://127.0.0.1:8551
    --jwt-secret <FILE>          hex JWT secret shared with the engine
    --log <FILTER>               log filter, such as info,axiom_node=debug [default: info]
    --log-format <FORMAT>        compact, pretty, or json [default: compact]
    -h, --help                   print this help
    -V, --version                print the version
";

/// Default address of the beacon API, the port every client uses.
const DEFAULT_HTTP_ADDRESS: &str = "127.0.0.1:5052";

/// Default libp2p address, the port every client uses.
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:9000";

/// What the command line asks for.
#[derive(Debug)]
pub(crate) enum Command {
    /// Print the usage text.
    Help,
    /// Print the version.
    Version,
    /// Run a node.
    Run(Box<Run>),
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
    /// Only one of the engine endpoint and its secret was given.
    #[error("--execution-endpoint and --jwt-secret go together")]
    IncompleteEngine,
    /// Genesis and checkpoint files were mixed, or a checkpoint file is missing.
    #[error("give either --genesis-state, or both --checkpoint-state and --checkpoint-block")]
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
    /// Peers to dial at startup.
    boot_nodes: Vec<Multiaddr>,
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
}

impl Cli {
    /// Parses arguments, without the program name.
    ///
    /// # Errors
    ///
    /// Fails on an unknown flag, a missing value, or a value that does not parse.
    pub(crate) fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Command, CliError> {
        let mut cli = Self::default();
        let mut arguments = arguments.into_iter();
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
                "--listen-address" => {
                    cli.listen_address = Some(Self::parsed(
                        "--listen-address",
                        value("--listen-address")?,
                    )?);
                }
                "--boot-node" => {
                    let text = value("--boot-node")?;
                    cli.boot_nodes.push(Self::parsed("--boot-node", text)?);
                }
                "--custody-groups" => {
                    let text = value("--custody-groups")?;
                    cli.custody_groups = Some(Self::parsed("--custody-groups", text)?);
                }
                "--no-network" => cli.no_network = true,
                "--discovery-port" => {
                    let text = value("--discovery-port")?;
                    cli.discovery_port = Some(Self::parsed("--discovery-port", text)?);
                }
                "--enr-address" => {
                    let text = value("--enr-address")?;
                    cli.enr_address = Some(Self::parsed("--enr-address", text)?);
                }
                "--boot-enr" => {
                    let text = value("--boot-enr")?;
                    cli.boot_enrs.push(Self::parsed("--boot-enr", text)?);
                }
                "--no-discovery" => cli.no_discovery = true,
                "--execution-endpoint" => {
                    cli.execution_endpoint = Some(value("--execution-endpoint")?);
                }
                "--jwt-secret" => cli.jwt_secret = Some(value("--jwt-secret")?.into()),
                "--log" => cli.log = Some(value("--log")?),
                "--log-format" => {
                    cli.log_format = Some(Self::log_format(value("--log-format")?)?);
                }
                _ => return Err(CliError::UnknownFlag(flag)),
            }
        }
        cli.resolve().map(|run| Command::Run(Box::new(run)))
    }

    /// Turns the flags into a run, reading the config file if one is named.
    fn resolve(self) -> Result<Run, CliError> {
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
            Some(NetworkSettings {
                listen_address,
                boot_nodes: self.boot_nodes,
                discovery,
                // Every node keeps at least the spec's minimum.
                custody_group_count: self
                    .custody_groups
                    .unwrap_or(chain.custody_requirement)
                    .max(chain.custody_requirement),
            })
        };
        // A checkpoint needs both its files, and replaces genesis.
        let anchor = match (
            self.genesis_state,
            self.checkpoint_state,
            self.checkpoint_block,
        ) {
            (None, None, None) => None,
            (Some(genesis), None, None) => Some(AnchorSource::Genesis(genesis)),
            (None, Some(state), Some(block)) => Some(AnchorSource::Checkpoint { state, block }),
            _ => return Err(CliError::ConflictingAnchors),
        };
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
        if let Some(path) = &self.config {
            let text = fs::read_to_string(path).map_err(|source| CliError::ConfigFile {
                path: path.clone(),
                source,
            })?;
            let yaml = Yaml::parse(&text).map_err(|source| CliError::ConfigYaml {
                path: path.clone(),
                source,
            })?;
            // The file's own preset base wins over the network flag.
            let preset = match yaml.get("PRESET_BASE").and_then(Yaml::as_str) {
                Some("minimal") => PresetName::Minimal,
                _ => PresetName::Mainnet,
            };
            let chain = ChainConfig::from_yaml(&yaml).map_err(|source| CliError::Config {
                path: path.clone(),
                source,
            })?;
            return Ok((preset, chain));
        }
        match self.network.as_deref() {
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
    fn log_format(value: String) -> Result<LogFormat, CliError> {
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
                    boot_nodes: Vec::new(),
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
                    boot_nodes: vec!["/ip4/10.0.0.1/tcp/9000".parse().unwrap()],
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
                "--genesis-state",
                "g.ssz",
                "--checkpoint-state",
                "s.ssz",
                "--checkpoint-block",
                "b.ssz"
            ]),
            Err(CliError::ConflictingAnchors)
        ));
        // An engine needs both its endpoint and its secret.
        assert!(matches!(
            parse(&["--execution-endpoint", "http://127.0.0.1:8551"]),
            Err(CliError::IncompleteEngine)
        ));
    }
}
