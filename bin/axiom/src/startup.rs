//! What the node does before it starts: purge its database, and write out its configuration.

use std::{
    fs,
    io::{self, BufRead, IsTerminal},
    path::{Path, PathBuf},
};

use axiom_json::Json;
use axiom_node::{BeaconApi, NodeConfig};
use axiom_types::ChainConfig;
use thiserror::Error;
use tracing::{info, warn};

use crate::{cli::Purge, node_json::NodeJson, run::PresetName};

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

/// Files the resolved configurations are written to before the node starts, as JSON.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Dumps {
    /// Where the node configuration goes.
    pub(crate) config: Option<PathBuf>,
    /// Where the chain configuration goes, under its config.yaml names.
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
        let write = |path: &PathBuf, json: Json| {
            fs::write(path, format!("{json}\n")).map_err(|error| StartupError::Dump {
                path: path.clone(),
                error,
            })
        };
        if let Some(path) = &self.config {
            write(path, NodeJson(node).to_json())?;
        }
        if let Some(path) = &self.chain_config {
            // The spec route's rendering, so the dump and the API agree byte for byte.
            write(path, BeaconApi::chain_config_json(chain, preset.name()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    #[test]
    fn dumps_write_both_files_as_json() {
        let directory = env::temp_dir().join(format!("axiom-dumps-{}", process::id()));
        fs::create_dir_all(&directory).unwrap();
        let dumps = Dumps {
            config: Some(directory.join("node.json")),
            chain_config: Some(directory.join("config.json")),
        };
        let node = NodeConfig::default();
        let chain = ChainConfig::minimal();
        dumps.write(&node, &chain, PresetName::Minimal).unwrap();

        // Each file is the JSON text of its rendering, on one line.
        let written = fs::read_to_string(directory.join("node.json")).unwrap();
        assert_eq!(written, format!("{}\n", NodeJson(&node).to_json()));
        let written = fs::read_to_string(directory.join("config.json")).unwrap();
        let parsed = Json::parse(written.trim_end().as_bytes()).unwrap();
        assert_eq!(parsed, BeaconApi::chain_config_json(&chain, "minimal"));

        // Keys are the config.yaml names, scalars strings, as the spec route writes them.
        let Json::Object(object) = parsed else {
            panic!("expected an object");
        };
        assert_eq!(object.get("PRESET_BASE"), Some(&Json::from("minimal")));
        assert_eq!(
            object.get("MIN_GENESIS_TIME"),
            Some(&Json::from(chain.min_genesis_time.to_string()))
        );
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
