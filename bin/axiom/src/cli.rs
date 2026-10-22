//! The command line: flags parsed by hand into a typed configuration.

use std::{error::Error, fmt, fs, io, net::SocketAddr, path::PathBuf};

use axiom_node::{EngineConfig, NodeConfig};
use axiom_telemetry::{LogConfig, LogFormat};
use axiom_types::{ChainConfig, ConfigError};
use axiom_yaml::Yaml;

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
    --datadir <DIR>              database directory [default: in memory]
    --http-address <ADDR>        beacon API address [default: 127.0.0.1:5052]
    --no-http                    disable the beacon API
    --metrics-address <ADDR>     Prometheus endpoint address [default: disabled]
    --execution-endpoint <URL>   engine API endpoint, such as http://127.0.0.1:8551
    --jwt-secret <FILE>          hex JWT secret shared with the engine
    --log <FILTER>               log filter, such as info,axiom_node=debug [default: info]
    --log-format <FORMAT>        compact, pretty, or json [default: compact]
    -h, --help                   print this help
    -V, --version                print the version
";

/// Default address of the beacon API, the port every client uses.
const DEFAULT_HTTP_ADDRESS: &str = "127.0.0.1:5052";

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
#[derive(Debug)]
pub(crate) enum CliError {
    /// A flag this client does not know.
    UnknownFlag(String),
    /// A flag that needs a value came last.
    MissingValue(&'static str),
    /// A flag's value does not parse.
    InvalidValue {
        /// The flag.
        flag: &'static str,
        /// The value given.
        value: String,
    },
    /// Only one of the engine endpoint and its secret was given.
    IncompleteEngine,
    /// The config file cannot be read.
    ConfigFile(io::Error),
    /// The config file is not valid YAML.
    ConfigYaml(String),
    /// The config file has a bad value.
    Config(ConfigError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFlag(flag) => write!(f, "unknown flag {flag}"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a value"),
            Self::InvalidValue { flag, value } => write!(f, "invalid value for {flag}: {value}"),
            Self::IncompleteEngine => {
                f.write_str("--execution-endpoint and --jwt-secret go together")
            }
            Self::ConfigFile(error) => write!(f, "cannot read the config file: {error}"),
            Self::ConfigYaml(error) => write!(f, "config file is not YAML: {error}"),
            Self::Config(error) => write!(f, "config file: {error}"),
        }
    }
}

impl Error for CliError {}

/// The flags as given, before they are resolved into a configuration.
#[derive(Debug, Default)]
pub(crate) struct Cli {
    /// The network name.
    network: Option<String>,
    /// The config file.
    config: Option<PathBuf>,
    /// The genesis state file.
    genesis_state: Option<PathBuf>,
    /// The database directory.
    datadir: Option<PathBuf>,
    /// The beacon API address.
    http_address: Option<SocketAddr>,
    /// Whether the beacon API is off.
    no_http: bool,
    /// The metrics address.
    metrics_address: Option<SocketAddr>,
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
                "--datadir" => cli.datadir = Some(value("--datadir")?.into()),
                "--http-address" => {
                    cli.http_address =
                        Some(Self::address("--http-address", value("--http-address")?)?);
                }
                "--no-http" => cli.no_http = true,
                "--metrics-address" => {
                    cli.metrics_address = Some(Self::address(
                        "--metrics-address",
                        value("--metrics-address")?,
                    )?);
                }
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
        let http_address = if self.no_http {
            None
        } else {
            Some(self.http_address.unwrap_or_else(Self::default_http_address))
        };
        Ok(Run {
            preset,
            chain,
            node: NodeConfig {
                data_dir: self.datadir,
                genesis_state: self.genesis_state,
                http_address,
                metrics_address: self.metrics_address,
                engine,
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
            let text = fs::read_to_string(path).map_err(CliError::ConfigFile)?;
            let yaml =
                Yaml::parse(&text).map_err(|error| CliError::ConfigYaml(error.to_string()))?;
            // The file's own preset base wins over the network flag.
            let preset = match yaml.get("PRESET_BASE").and_then(Yaml::as_str) {
                Some("minimal") => PresetName::Minimal,
                _ => PresetName::Mainnet,
            };
            let chain = ChainConfig::from_yaml(&yaml).map_err(CliError::Config)?;
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

    /// A socket address flag.
    fn address(flag: &'static str, value: String) -> Result<SocketAddr, CliError> {
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

    /// The beacon API's default address.
    fn default_http_address() -> SocketAddr {
        // Invariant: the constant is a literal IPv4 socket address, so it always parses.
        DEFAULT_HTTP_ADDRESS
            .parse()
            .expect("the default address is a valid literal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        ]);

        assert_eq!(run.preset, PresetName::Minimal);
        assert_eq!(run.chain, ChainConfig::minimal());
        assert_eq!(
            run.node,
            NodeConfig {
                data_dir: Some("data".into()),
                genesis_state: Some("genesis.ssz".into()),
                http_address: None,
                metrics_address: Some("0.0.0.0:5054".parse().unwrap()),
                engine: Some(EngineConfig {
                    url: "http://127.0.0.1:8551".to_owned(),
                    jwt_secret: "jwt.hex".into(),
                }),
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
        // An engine needs both its endpoint and its secret.
        assert!(matches!(
            parse(&["--execution-endpoint", "http://127.0.0.1:8551"]),
            Err(CliError::IncompleteEngine)
        ));
    }
}
