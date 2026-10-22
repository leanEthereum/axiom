//! The command line: flags parsed by hand into a typed configuration.

pub(crate) mod arguments;
pub(crate) mod log;
mod node;

use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use arguments::Arguments;
use axiom_slasher::LayoutError;
use axiom_types::{ChainConfig, ConfigError};
use axiom_yaml::{ParseError, Yaml};
pub(crate) use node::Purge;
use node::{NODE_USAGE, NodeFlags};
use thiserror::Error;

use crate::{
    account::Account,
    database::DatabaseCommand,
    manager::Manager,
    network::{BuiltInNetwork, Network, NetworkError, UnknownNetwork},
    run::{PresetName, Run},
    validator::ValidatorCommand,
};

/// The opening of the usage text, before the beacon node's flags.
const USAGE_HEAD: &str = "\
axiom: an Ethereum consensus client

USAGE:
    axiom [OPTIONS]
    axiom validator [OPTIONS]            run the validator client; see axiom validator --help
    axiom account <COMMAND> [OPTIONS]    keys, deposits, and slashing protection files
    axiom validator-manager <COMMAND>    create validators, and manage running clients' keys
    axiom db <COMMAND> [OPTIONS]         maintain a stopped node's database; see axiom db --help

OPTIONS:
";

/// The close of the usage text.
const USAGE_TAIL: &str = "\
    -h, --help                   print this help
    -V, --version                print the version
";

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
    /// Run a validator manager command.
    Manager(Box<Manager>),
    /// Run a database command.
    Database(DatabaseCommand),
}

/// Why the command line cannot be used.
#[derive(Debug, Error)]
pub(crate) enum CliError {
    /// A flag this client does not know.
    #[error("unknown flag {0}")]
    UnknownFlag(String),
    /// A command word this client does not know.
    #[error("unknown command {0}")]
    UnknownCommand(String),
    /// A command family was named without a command.
    #[error("{0} needs a command")]
    MissingCommand(&'static str),
    /// A flag that needs a value came last.
    #[error("{0} needs a value")]
    MissingValue(&'static str),
    /// A required flag is missing.
    #[error("{0} is required")]
    MissingFlag(&'static str),
    /// A flag's value does not parse.
    #[error("invalid value for {flag}: {value}")]
    InvalidValue {
        /// The flag.
        flag: &'static str,
        /// The value given.
        value: String,
    },
    /// A flag was given without another it needs.
    #[error("{flag} needs {needs}")]
    Requires {
        /// The flag given.
        flag: &'static str,
        /// The flag it needs.
        needs: &'static str,
    },
    /// Two flags that exclude each other were both given.
    #[error("{flag} and {other} cannot be given together")]
    Conflicts {
        /// The first flag.
        flag: &'static str,
        /// The other flag.
        other: &'static str,
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
    #[error("give both --checkpoint-state and --checkpoint-block, or --checkpoint-sync-url")]
    ConflictingAnchors,
    /// A network was named twice over.
    #[error("give one of --network, --testnet-dir, and --config")]
    ConflictingNetworks,
    /// A network name is not compiled in.
    #[error("--network: {0}")]
    UnknownNetwork(#[from] UnknownNetwork),
    /// A network's files cannot be used.
    #[error("network: {0}")]
    Network(#[from] NetworkError),
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

/// The command line's entry points.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cli;

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
        if arguments
            .next_if(|word| word == "validator-manager")
            .is_some()
        {
            return Manager::parse(arguments).map(|manager| Command::Manager(Box::new(manager)));
        }
        if arguments.next_if(|word| word == "validator").is_some() {
            return ValidatorCommand::parse(arguments).map(Command::Validator);
        }
        if arguments.next_if(|word| word == "db").is_some() {
            return DatabaseCommand::parse(Arguments::new(arguments)).map(Command::Database);
        }
        NodeFlags::parse(Arguments::new(arguments))
    }

    /// The usage text, shown by the help flag.
    pub(crate) fn usage() -> String {
        let mut usage = USAGE_HEAD.to_owned();
        for section in NODE_USAGE {
            usage.push_str(section);
        }
        usage.push_str(USAGE_TAIL);
        usage
    }

    /// The preset and chain configuration a network name, a network directory, or a config file names.
    ///
    /// A config file wins over the network name.
    /// A network directory excludes both, as on the beacon node.
    pub(crate) fn choose_chain(
        network: Option<&str>,
        testnet_dir: Option<&Path>,
        config: Option<&Path>,
    ) -> Result<(PresetName, ChainConfig), CliError> {
        if let Some(directory) = testnet_dir {
            if network.is_some() || config.is_some() {
                return Err(CliError::ConflictingNetworks);
            }
            let network = Network::load(directory)?;
            return Ok((network.preset, network.chain));
        }
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
            let preset = PresetName::of_config(&yaml);
            let chain = ChainConfig::from_yaml(&yaml).map_err(|source| CliError::Config {
                path: path.to_owned(),
                source,
            })?;
            return Ok((preset, chain));
        }
        let name = match network {
            Some(name) => name.parse()?,
            None => BuiltInNetwork::default(),
        };
        let network = Network::built_in(name)?;
        Ok((network.preset, network.chain))
    }

    /// Any flag whose value parses from text.
    pub(crate) fn parsed<T: FromStr>(flag: &'static str, value: String) -> Result<T, CliError> {
        value
            .parse()
            .map_err(|_| CliError::InvalidValue { flag, value })
    }

    /// A default address from its literal.
    pub(crate) fn default_address(literal: &str) -> SocketAddr {
        // Invariant: every default is a literal IPv4 socket address, so it always parses.
        literal
            .parse()
            .expect("default addresses are valid literals")
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    #[test]
    fn a_network_directory_names_the_chain_of_every_command() {
        // Fixture state: a minimal-preset devnet directory with its two required files.
        let directory = env::temp_dir().join(format!("axiom-cli-devnet-{}", process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("config.yaml"),
            "PRESET_BASE: minimal\nCONFIG_NAME: devnet\n",
        )
        .unwrap();
        fs::write(directory.join("deposit_contract_block.txt"), "0\n").unwrap();

        // The directory alone picks the preset and the chain from its config file.
        let chosen = Cli::choose_chain(None, Some(&directory), None).unwrap();
        assert_eq!(
            chosen,
            (
                PresetName::Minimal,
                ChainConfig {
                    config_name: "devnet".to_owned(),
                    ..ChainConfig::minimal()
                }
            )
        );

        // Beside a network name or a config file it is ambiguous, as on the beacon node.
        assert!(matches!(
            Cli::choose_chain(Some("minimal"), Some(&directory), None),
            Err(CliError::ConflictingNetworks)
        ));
        let config = directory.join("config.yaml");
        assert!(matches!(
            Cli::choose_chain(None, Some(&directory), Some(&config)),
            Err(CliError::ConflictingNetworks)
        ));
        fs::remove_dir_all(&directory).unwrap();
    }
}
