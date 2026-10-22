//! What the node does before it starts: purge its database, and write out its configuration.

use std::{
    fmt::{self, Display},
    fs,
    io::{self, BufRead, IsTerminal},
    path::{Path, PathBuf},
};

use axiom_node::NodeConfig;
use axiom_types::{ChainConfig, ConfigValue};
use thiserror::Error;
use tracing::{info, warn};

use crate::{cli::Purge, run::PresetName};

/// The word an operator types to confirm a purge.
const PURGE_CONFIRMATION: &str = "confirm";

/// Why the node did not start.
#[derive(Debug, Error)]
pub(crate) enum StartupError {
    /// The operator did not confirm the purge.
    #[error("the database was not deleted; the node stops rather than run on it")]
    PurgeDeclined,
    /// The database could not be deleted.
    #[error("deleting the database {}: {error}", .path.display())]
    Purge {
        /// The database directory.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
    /// A configuration could not be written out.
    #[error("writing {}: {error}", .path.display())]
    Dump {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
}

impl Purge {
    /// Deletes the chain database under a data directory, asking first unless forced.
    ///
    /// Asking needs a terminal; without one the database stays and a warning says how to force it.
    pub(crate) fn apply(self, datadir: &Path) -> Result<(), StartupError> {
        let database = datadir.join("chain");
        if !database.exists() {
            return Ok(());
        }
        if self == Self::Confirmed {
            let stdin = io::stdin();
            if !stdin.is_terminal() {
                warn!(
                    "--purge-db needs a terminal to confirm; the database stays, use --purge-db-force"
                );
                return Ok(());
            }
            info!("about to delete the chain database; the node will sync again from scratch");
            info!("type {PURGE_CONFIRMATION} to delete it, anything else to stop");
            let mut answer = String::new();
            // An unreadable terminal counts as a refusal.
            let _read = stdin.lock().read_line(&mut answer);
            if answer.trim() != PURGE_CONFIRMATION {
                return Err(StartupError::PurgeDeclined);
            }
        }
        fs::remove_dir_all(&database).map_err(|error| StartupError::Purge {
            path: database.clone(),
            error,
        })?;
        info!(path = %database.display(), "chain database deleted");
        Ok(())
    }
}

/// Files the resolved configurations are written to before the node starts.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Dumps {
    /// Where the node configuration goes, as Rust debug text.
    pub(crate) config: Option<PathBuf>,
    /// Where the chain configuration goes, as the spec's YAML.
    pub(crate) chain_config: Option<PathBuf>,
}

impl Dumps {
    /// Writes each configuration asked for.
    pub(crate) fn write(
        &self,
        node: &NodeConfig,
        chain: &ChainConfig,
        preset: PresetName,
    ) -> Result<(), StartupError> {
        let write = |path: &PathBuf, text: String| {
            fs::write(path, text).map_err(|error| StartupError::Dump {
                path: path.clone(),
                error,
            })
        };
        if let Some(path) = &self.config {
            write(path, format!("{node:#?}\n"))?;
        }
        if let Some(path) = &self.chain_config {
            write(path, ChainYaml { chain, preset }.to_string())?;
        }
        Ok(())
    }
}

/// A chain configuration written as the spec's configuration files write it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChainYaml<'a> {
    /// The configuration.
    pub(crate) chain: &'a ChainConfig,
    /// The preset it was built for.
    pub(crate) preset: PresetName,
}

impl Display for ChainYaml<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (key, value) in self.chain.entries(self.preset.name()) {
            match value {
                ConfigValue::Number(number) => writeln!(f, "{key}: {number}")?,
                // Quotes keep hex and long decimals as text, as the spec files write them.
                ConfigValue::Text(text) => writeln!(f, "{key}: '{text}'")?,
                ConfigValue::Schedule(entries) if entries.is_empty() => writeln!(f, "{key}: []")?,
                ConfigValue::Schedule(entries) => {
                    writeln!(f, "{key}:")?;
                    for (epoch, blobs) in entries {
                        writeln!(f, "  - EPOCH: {epoch}")?;
                        writeln!(f, "    MAX_BLOBS_PER_BLOCK: {blobs}")?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use axiom_types::{BlobParameters, BlobSchedule, Epoch};
    use axiom_yaml::Yaml;

    use super::*;

    /// Reads a written configuration back.
    fn reread(chain: &ChainConfig, preset: PresetName) -> ChainConfig {
        let text = ChainYaml { chain, preset }.to_string();
        let yaml = Yaml::parse(&text).unwrap();
        ChainConfig::from_yaml(&yaml).unwrap()
    }

    #[test]
    fn written_chain_configurations_read_back_whole() {
        // Mainnet has a blob schedule; minimal has none and every fork in the far future.
        assert_eq!(
            reread(&ChainConfig::mainnet(), PresetName::Mainnet),
            ChainConfig::mainnet()
        );
        assert_eq!(
            reread(&ChainConfig::minimal(), PresetName::Minimal),
            ChainConfig::minimal()
        );
        // An emptied schedule stays empty rather than taking the base's.
        let unscheduled = ChainConfig {
            blob_schedule: BlobSchedule::new(Vec::new()),
            ..ChainConfig::mainnet()
        };
        assert_eq!(reread(&unscheduled, PresetName::Mainnet), unscheduled);
        // A one-entry schedule keeps its entry.
        let scheduled = ChainConfig {
            blob_schedule: BlobSchedule::new(vec![BlobParameters {
                epoch: Epoch(7),
                max_blobs_per_block: 3,
            }]),
            ..ChainConfig::minimal()
        };
        assert_eq!(reread(&scheduled, PresetName::Minimal), scheduled);
    }

    #[test]
    fn dumps_write_both_files() {
        let directory = env::temp_dir().join(format!("axiom-dumps-{}", process::id()));
        fs::create_dir_all(&directory).unwrap();
        let dumps = Dumps {
            config: Some(directory.join("node.txt")),
            chain_config: Some(directory.join("config.yaml")),
        };
        dumps
            .write(
                &NodeConfig::default(),
                &ChainConfig::minimal(),
                PresetName::Minimal,
            )
            .unwrap();

        let node = fs::read_to_string(directory.join("node.txt")).unwrap();
        assert_eq!(node, format!("{:#?}\n", NodeConfig::default()));
        let chain = fs::read_to_string(directory.join("config.yaml")).unwrap();
        assert!(chain.starts_with("PRESET_BASE: 'minimal'\n"), "{chain}");
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_forced_purge_deletes_only_the_chain_database() {
        // Fixture state: a data directory with a chain database and a node key beside it.
        let datadir = env::temp_dir().join(format!("axiom-purge-{}", process::id()));
        fs::create_dir_all(datadir.join("chain")).unwrap();
        fs::create_dir_all(datadir.join("network")).unwrap();
        fs::write(datadir.join("chain").join("segment"), b"data").unwrap();

        Purge::Forced.apply(&datadir).unwrap();

        assert!(!datadir.join("chain").exists());
        assert!(datadir.join("network").exists());
        // A second purge finds nothing to delete and succeeds.
        Purge::Forced.apply(&datadir).unwrap();
        fs::remove_dir_all(&datadir).unwrap();
    }
}
