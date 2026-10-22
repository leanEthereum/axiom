//! Networks: a chain's configuration, its boot nodes, and its genesis state.
//!
//! # Overview
//!
//! A network is the files its maintainers publish:
//!
//! - `config.yaml`, the chain configuration, whose preset base picks the compiled preset.
//! - `bootstrap_nodes.yaml`, the discovery records to join through.
//! - `deposit_contract_block.txt`, the execution block that deployed the deposit contract.
//! - `genesis.ssz`, the genesis state, when it is small enough to ship.
//!
//! Well-known networks are compiled in.
//! Any other network loads from a directory holding the same files.

mod built_in;

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use axiom_discv5::{Enr, EnrError};
use axiom_node::{EmbeddedGenesis, GenesisState};
use axiom_types::{ChainConfig, ConfigError, Hash32};
use axiom_yaml::{ParseError, Yaml};
pub(crate) use built_in::{BuiltInNetwork, UnknownNetwork};
use thiserror::Error;

use crate::run::PresetName;

/// Name of the chain configuration file.
const CONFIG_FILE: &str = "config.yaml";

/// Name of the boot node file.
const BOOT_NODES_FILE: &str = "bootstrap_nodes.yaml";

/// Name of the deposit contract block file.
const DEPOSIT_BLOCK_FILE: &str = "deposit_contract_block.txt";

/// Name of the genesis state file.
const GENESIS_FILE: &str = "genesis.ssz";

/// A network's configuration, resolved and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Network {
    /// The compiled preset its states use.
    pub(crate) preset: PresetName,
    /// The chain configuration.
    pub(crate) chain: ChainConfig,
    /// Discovery records to join through.
    pub(crate) boot_enrs: Vec<Enr>,
    /// The execution block that deployed the deposit contract.
    pub(crate) deposit_contract_block: u64,
    /// How the genesis state is known.
    pub(crate) genesis: NetworkGenesis,
}

/// How a network's genesis state is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NetworkGenesis {
    /// The state itself is at hand, in the binary or in a file.
    Known(GenesisState),
    /// Only its SHA-256 is known; a beacon API must serve the bytes.
    Published(Hash32),
    /// Nothing is known, so the node needs a checkpoint or a genesis file.
    Unknown,
}

impl Network {
    /// A network from its configuration text and its other published files.
    fn from_parts(
        source: &Path,
        config: &str,
        boot_nodes: Option<&str>,
        deposit_block: &str,
        genesis: NetworkGenesis,
    ) -> Result<Self, NetworkError> {
        let file = |name: &str| source.join(name);
        let yaml = Yaml::parse(config).map_err(|error| NetworkError::Yaml {
            path: file(CONFIG_FILE),
            error,
        })?;
        let preset = PresetName::of_config(&yaml);
        let chain = ChainConfig::from_yaml(&yaml).map_err(|error| NetworkError::Config {
            path: file(CONFIG_FILE),
            error,
        })?;
        let boot_enrs = match boot_nodes {
            Some(text) => Self::boot_enrs(text).map_err(|error| error.at(file(BOOT_NODES_FILE)))?,
            None => Vec::new(),
        };
        let deposit_contract_block =
            deposit_block
                .trim()
                .parse()
                .map_err(|_| NetworkError::DepositBlock {
                    path: file(DEPOSIT_BLOCK_FILE),
                    text: deposit_block.trim().to_owned(),
                })?;
        Ok(Self {
            preset,
            chain,
            boot_enrs,
            deposit_contract_block,
            genesis,
        })
    }

    /// A network from a directory of its published files.
    ///
    /// The configuration and the deposit block are required.
    /// The boot nodes and the genesis state are optional; an empty genesis file counts as absent.
    ///
    /// # Errors
    ///
    /// Fails when a required file is missing, or any file does not parse.
    pub(crate) fn load(directory: &Path) -> Result<Self, NetworkError> {
        let read = |name: &str| {
            let path = directory.join(name);
            fs::read_to_string(&path).map_err(|error| NetworkError::File { path, error })
        };
        let config = read(CONFIG_FILE)?;
        let deposit_block = read(DEPOSIT_BLOCK_FILE)?;
        let boot_nodes = match read(BOOT_NODES_FILE) {
            Ok(text) => Some(text),
            Err(NetworkError::File { error, .. }) if error.kind() == io::ErrorKind::NotFound => {
                None
            }
            Err(error) => return Err(error),
        };
        let genesis_path = directory.join(GENESIS_FILE);
        let genesis = match fs::metadata(&genesis_path) {
            Ok(metadata) if metadata.len() > 0 => {
                NetworkGenesis::Known(GenesisState::File(genesis_path))
            }
            _ => NetworkGenesis::Unknown,
        };
        Self::from_parts(
            directory,
            &config,
            boot_nodes.as_deref(),
            &deposit_block,
            genesis,
        )
    }

    /// A compiled-in network, or a test configuration of the minimal preset.
    ///
    /// # Errors
    ///
    /// Fails only if a compiled-in file is malformed, which a unit test rules out.
    pub(crate) fn built_in(network: BuiltInNetwork) -> Result<Self, NetworkError> {
        let Some(files) = network.files() else {
            // The minimal preset ships a configuration but no network.
            return Ok(Self {
                preset: PresetName::Minimal,
                chain: ChainConfig::minimal(),
                boot_enrs: Vec::new(),
                deposit_contract_block: 0,
                genesis: NetworkGenesis::Unknown,
            });
        };
        let genesis = match (files.genesis, files.genesis_checksum) {
            (Some(framed), _) => NetworkGenesis::Known(GenesisState::Embedded(
                EmbeddedGenesis::new(network.name(), framed),
            )),
            (None, Some(checksum)) => NetworkGenesis::Published(checksum),
            (None, None) => NetworkGenesis::Unknown,
        };
        Self::from_parts(
            Path::new(network.name()),
            files.config,
            Some(files.boot_nodes),
            files.deposit_block,
            genesis,
        )
    }

    /// The discovery records listed in a boot node file.
    ///
    /// The file is a YAML sequence of records, each quoted or bare.
    fn boot_enrs(text: &str) -> Result<Vec<Enr>, BootNodeError> {
        let yaml = Yaml::parse(text).map_err(BootNodeError::Yaml)?;
        // A file of comments only parses to null: a network with no boot nodes yet.
        let Some(entries) = yaml.as_sequence() else {
            return match yaml {
                Yaml::Null => Ok(Vec::new()),
                _ => Err(BootNodeError::NotASequence),
            };
        };
        entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let text = entry.as_str().ok_or(BootNodeError::NotText { index })?;
                text.parse()
                    .map_err(|error| BootNodeError::Record { index, error })
            })
            .collect()
    }
}

/// Why a boot node file cannot be used, before its path is known.
#[derive(Debug)]
enum BootNodeError {
    /// The file is not YAML.
    Yaml(ParseError),
    /// The file is not a sequence.
    NotASequence,
    /// An entry is not text.
    NotText {
        /// The entry's position.
        index: usize,
    },
    /// An entry is not a valid record.
    Record {
        /// The entry's position.
        index: usize,
        /// Why the record is refused.
        error: EnrError,
    },
}

impl BootNodeError {
    /// The error, naming the file it came from.
    fn at(self, path: PathBuf) -> NetworkError {
        match self {
            Self::Yaml(error) => NetworkError::Yaml { path, error },
            Self::NotASequence => NetworkError::BootNodes { path },
            Self::NotText { index } => NetworkError::BootNodeText { path, index },
            Self::Record { index, error } => NetworkError::BootNode { path, index, error },
        }
    }
}

/// Why a network's files cannot be used.
#[derive(Debug, Error)]
pub(crate) enum NetworkError {
    /// A file cannot be read.
    #[error("cannot read {}: {error}", .path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
    /// A file is not YAML.
    #[error("{} is not YAML: {error}", .path.display())]
    Yaml {
        /// The file.
        path: PathBuf,
        /// Where and why the parser stopped.
        #[source]
        error: ParseError,
    },
    /// The chain configuration has a bad value.
    #[error("{}: {error}", .path.display())]
    Config {
        /// The configuration file.
        path: PathBuf,
        /// The key and the value that is wrong.
        #[source]
        error: ConfigError,
    },
    /// The boot node file is not a sequence of records.
    #[error("{} is not a sequence of node records", .path.display())]
    BootNodes {
        /// The boot node file.
        path: PathBuf,
    },
    /// A boot node entry is not text.
    #[error("{} entry {index} is not text", .path.display())]
    BootNodeText {
        /// The boot node file.
        path: PathBuf,
        /// The entry's position, from zero.
        index: usize,
    },
    /// A boot node entry is not a valid node record.
    #[error("{} entry {index}: {error}", .path.display())]
    BootNode {
        /// The boot node file.
        path: PathBuf,
        /// The entry's position, from zero.
        index: usize,
        /// Why the record is refused.
        #[source]
        error: EnrError,
    },
    /// The deposit contract block is not a block number.
    #[error("{} holds {text:?}, not a block number", .path.display())]
    DepositBlock {
        /// The deposit block file.
        path: PathBuf,
        /// The text it holds.
        text: String,
    },
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    /// The example record of EIP-778.
    const EIP_778_RECORD: &str = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    /// A directory under the system's temporary directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = env::temp_dir().join(format!("axiom-network-{name}-{}", process::id()));
            let _stale = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, contents: &[u8]) {
            fs::write(self.0.join(name), contents).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_testnet_directory_loads_every_file() {
        // A minimal-preset devnet with one boot node, a deposit block, and a genesis file.
        let dir = Scratch::new("full");
        dir.write(CONFIG_FILE, b"PRESET_BASE: minimal\nCONFIG_NAME: devnet\n");
        dir.write(
            BOOT_NODES_FILE,
            format!("# devnet\n- \"{EIP_778_RECORD}\"\n").as_bytes(),
        );
        dir.write(DEPOSIT_BLOCK_FILE, b"17\n");
        dir.write(GENESIS_FILE, &[0; 4]);

        let network = Network::load(&dir.0).unwrap();

        assert_eq!(
            network,
            Network {
                preset: PresetName::Minimal,
                chain: ChainConfig {
                    config_name: "devnet".to_owned(),
                    ..ChainConfig::minimal()
                },
                boot_enrs: vec![EIP_778_RECORD.parse().unwrap()],
                deposit_contract_block: 17,
                genesis: NetworkGenesis::Known(GenesisState::File(dir.0.join(GENESIS_FILE))),
            }
        );
    }

    #[test]
    fn optional_files_may_be_missing_or_empty() {
        // No boot nodes, and an empty genesis file, as a network before its genesis publishes.
        let dir = Scratch::new("bare");
        dir.write(CONFIG_FILE, b"PRESET_BASE: gnosis\n");
        dir.write(DEPOSIT_BLOCK_FILE, b"0");
        dir.write(GENESIS_FILE, b"");

        let network = Network::load(&dir.0).unwrap();

        assert_eq!(network.preset, PresetName::Gnosis);
        assert_eq!(network.boot_enrs, Vec::new());
        assert_eq!(network.genesis, NetworkGenesis::Unknown);
    }

    #[test]
    fn broken_files_name_themselves() {
        let dir = Scratch::new("broken");

        // The deposit block file is required.
        dir.write(CONFIG_FILE, b"PRESET_BASE: minimal\n");
        assert!(matches!(
            Network::load(&dir.0),
            Err(NetworkError::File { path, .. }) if path == dir.0.join(DEPOSIT_BLOCK_FILE)
        ));

        // A deposit block in words is refused with its text.
        dir.write(DEPOSIT_BLOCK_FILE, b"genesis\n");
        assert!(matches!(
            Network::load(&dir.0),
            Err(NetworkError::DepositBlock { text, .. }) if text == "genesis"
        ));

        // The second boot node is cut short, so it is named by its position.
        dir.write(DEPOSIT_BLOCK_FILE, b"0\n");
        dir.write(
            BOOT_NODES_FILE,
            format!("- {EIP_778_RECORD}\n- enr:-IS4QHCY\n").as_bytes(),
        );
        assert!(matches!(
            Network::load(&dir.0),
            Err(NetworkError::BootNode { index: 1, .. })
        ));

        // A mapping is not a list of records.
        dir.write(BOOT_NODES_FILE, b"node: enr:abc\n");
        assert!(matches!(
            Network::load(&dir.0),
            Err(NetworkError::BootNodes { .. })
        ));

        // An unknown preset base is refused by the chain configuration.
        dir.write(BOOT_NODES_FILE, b"");
        dir.write(CONFIG_FILE, b"PRESET_BASE: holesky\n");
        assert!(matches!(
            Network::load(&dir.0),
            Err(NetworkError::Config {
                error: ConfigError::UnknownPresetBase(_),
                ..
            })
        ));
    }
}
