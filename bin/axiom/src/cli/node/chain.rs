//! Which chain the node follows, and where it starts on an empty database.

use std::{path::PathBuf, time::Duration};

use axiom_node::{
    AnchorSource, CheckpointServer, GenesisDownload, GenesisState, HistorySettings,
    SnapshotInterval, StorageMode, WeakSubjectivity,
};

use crate::{
    cli::{Cli, CliError, arguments::Arguments},
    network::{BuiltInNetwork, Network, NetworkGenesis},
};

/// Default longest wait for a genesis state download.
///
/// Test network states reach hundreds of megabytes, so five minutes leave room on a slow link.
const DEFAULT_GENESIS_TIMEOUT: Duration = Duration::from_secs(300);

/// The usage lines of the chain flags.
pub(crate) const CHAIN_USAGE: &str = "\
    --network <NAME>             mainnet, sepolia, holesky, hoodi, gnosis, chiado, or minimal
                                 [default: mainnet]
    --testnet-dir <DIR>          a network's config.yaml, bootstrap_nodes.yaml,
                                 deposit_contract_block.txt, and optional genesis.ssz
    --config <FILE>              chain config YAML alone; its PRESET_BASE picks the preset
    --genesis-state <FILE>       SSZ genesis state, instead of the network's
                                 with a checkpoint, it lets an archive rebuild older states
    --genesis-state-url <URL>    beacon API serving the genesis state, when the binary lacks it
    --genesis-state-url-timeout <SECONDS>
                                 longest wait for the genesis state [default: 300]
    --checkpoint-state <FILE>    SSZ post-state of a trusted block, instead of genesis
    --checkpoint-block <FILE>    SSZ signed trusted block, with --checkpoint-state
    --checkpoint-sync-url <URL>  trusted beacon API to download the finalized checkpoint from
    --checkpoint-sync-url-timeout <SECONDS>
                                 longest wait for each checkpoint download [default: 180]
    --weak-subjectivity-checkpoint <ROOT:EPOCH>
                                 block root and epoch the chain must pass through
    --allow-insecure-genesis-sync
                                 sync from genesis even after its blobs left the peer window
    --ignore-ws-check            only warn when the head is past its weak subjectivity period
    --archive                    keep state snapshots and backfill to genesis
    --snapshot-interval <SLOTS>  slots between archive snapshots [default: 2048]
";

/// The chain flags as given.
#[derive(Debug, Default)]
pub(crate) struct ChainFlags {
    /// The network name.
    network: Option<BuiltInNetwork>,
    /// A network directory.
    testnet_dir: Option<PathBuf>,
    /// A chain configuration file alone.
    config: Option<PathBuf>,
    /// The genesis state file.
    genesis_state: Option<PathBuf>,
    /// The beacon API serving the genesis state.
    genesis_state_url: Option<String>,
    /// Longest wait for the genesis state, in seconds.
    genesis_state_url_timeout: Option<u64>,
    /// The checkpoint state file.
    checkpoint_state: Option<PathBuf>,
    /// The checkpoint block file.
    checkpoint_block: Option<PathBuf>,
    /// The beacon API to download a checkpoint from.
    checkpoint_sync_url: Option<String>,
    /// Longest wait for each checkpoint download, in seconds.
    checkpoint_sync_url_timeout: Option<u64>,
    /// The checkpoint the chain must pass through.
    weak_subjectivity: Option<WeakSubjectivity>,
    /// Slots between archive snapshots, given only in archive mode.
    snapshot_interval: Option<SnapshotInterval>,
    /// Whether to sync from genesis whatever its age.
    allow_insecure_genesis_sync: bool,
    /// Whether a stale head only warns.
    ignore_ws_check: bool,
}

/// What the chain flags resolve to.
#[derive(Debug)]
pub(crate) struct ChainChoice {
    /// The network followed.
    pub(crate) network: Network,
    /// Where an empty database starts.
    pub(crate) anchor: Option<AnchorSource>,
    /// History, pruning, and weak subjectivity.
    pub(crate) history: HistorySettings,
}

impl ChainFlags {
    /// Takes a chain flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--network" => self.network = Some(words.parsed("--network")?),
            "--testnet-dir" => self.testnet_dir = Some(words.path("--testnet-dir")?),
            "--config" => self.config = Some(words.path("--config")?),
            "--genesis-state" => self.genesis_state = Some(words.path("--genesis-state")?),
            "--genesis-state-url" => {
                self.genesis_state_url = Some(words.value("--genesis-state-url")?);
            }
            "--genesis-state-url-timeout" => {
                self.genesis_state_url_timeout = Some(words.parsed("--genesis-state-url-timeout")?);
            }
            "--checkpoint-state" => self.checkpoint_state = Some(words.path("--checkpoint-state")?),
            "--checkpoint-block" => self.checkpoint_block = Some(words.path("--checkpoint-block")?),
            "--checkpoint-sync-url" => {
                self.checkpoint_sync_url = Some(words.value("--checkpoint-sync-url")?);
            }
            "--checkpoint-sync-url-timeout" => {
                self.checkpoint_sync_url_timeout =
                    Some(words.parsed("--checkpoint-sync-url-timeout")?);
            }
            "--weak-subjectivity-checkpoint" => {
                self.weak_subjectivity = Some(words.parsed("--weak-subjectivity-checkpoint")?);
            }
            "--archive" => {
                self.snapshot_interval
                    .get_or_insert(SnapshotInterval::DEFAULT);
            }
            "--snapshot-interval" => {
                self.snapshot_interval = Some(words.parsed("--snapshot-interval")?);
            }
            "--allow-insecure-genesis-sync" => self.allow_insecure_genesis_sync = true,
            "--ignore-ws-check" => self.ignore_ws_check = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The network, the anchor of an empty database, and the history settings.
    pub(crate) fn resolve(self) -> Result<ChainChoice, CliError> {
        let network = self.network()?;
        let checkpoint_timeout = self
            .checkpoint_sync_url_timeout
            .map_or(CheckpointServer::DEFAULT_TIMEOUT, Duration::from_secs);
        let genesis = self.genesis(&network.genesis, checkpoint_timeout);
        let mode = self
            .snapshot_interval
            .map_or(StorageMode::Pruned, StorageMode::Archive);

        // A checkpoint comes from both its files or from a server, and replaces genesis.
        // An archive anchored at a checkpoint then rebuilds older states from genesis, when known.
        let explicit_genesis = self.genesis_state.clone().map(GenesisState::File);
        let rebuild = explicit_genesis.or_else(|| match mode {
            StorageMode::Archive(_) => genesis.clone(),
            StorageMode::Pruned => None,
        });
        let (anchor, history_genesis) = match (
            self.checkpoint_state,
            self.checkpoint_block,
            self.checkpoint_sync_url,
        ) {
            (None, None, None) => (genesis.map(AnchorSource::Genesis), None),
            (Some(state), Some(block), None) => {
                (Some(AnchorSource::Checkpoint { state, block }), rebuild)
            }
            (None, None, Some(url)) => (
                Some(AnchorSource::Url {
                    url,
                    timeout: checkpoint_timeout,
                }),
                rebuild,
            ),
            _ => return Err(CliError::ConflictingAnchors),
        };
        Ok(ChainChoice {
            network,
            anchor,
            history: HistorySettings {
                mode,
                weak_subjectivity: self.weak_subjectivity,
                genesis: history_genesis,
                allow_insecure_genesis_sync: self.allow_insecure_genesis_sync,
                ignore_ws_check: self.ignore_ws_check,
            },
        })
    }

    /// The network followed: a directory, a configuration file alone, or a compiled-in name.
    fn network(&self) -> Result<Network, CliError> {
        match (&self.testnet_dir, &self.config, self.network) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(CliError::ConflictingNetworks),
            (Some(directory), None, None) => Ok(Network::load(directory)?),
            // A bare configuration names a chain but none of its boot nodes or genesis.
            (None, Some(path), _) => {
                let (preset, chain) = Cli::choose_chain(None, Some(path))?;
                Ok(Network {
                    preset,
                    chain,
                    boot_enrs: Vec::new(),
                    deposit_contract_block: 0,
                    genesis: NetworkGenesis::Unknown,
                })
            }
            (None, None, name) => Ok(Network::built_in(name.unwrap_or_default())?),
        }
    }

    /// The genesis state, from a file, from the network, or from a server.
    ///
    /// A server is asked only for a network that publishes its genesis digest.
    ///
    /// The checkpoint server also serves the genesis state, under its own timeout.
    fn genesis(
        &self,
        known: &NetworkGenesis,
        checkpoint_timeout: Duration,
    ) -> Option<GenesisState> {
        if let Some(path) = &self.genesis_state {
            return Some(GenesisState::File(path.clone()));
        }
        match known {
            NetworkGenesis::Known(state) => Some(state.clone()),
            NetworkGenesis::Published(checksum) => {
                let (url, timeout) = match (&self.genesis_state_url, &self.checkpoint_sync_url) {
                    (Some(url), _) => (
                        url.clone(),
                        self.genesis_state_url_timeout
                            .map_or(DEFAULT_GENESIS_TIMEOUT, Duration::from_secs),
                    ),
                    (None, Some(url)) => (url.clone(), checkpoint_timeout),
                    (None, None) => return None,
                };
                Some(GenesisState::Download(GenesisDownload {
                    url,
                    checksum: *checksum,
                    timeout,
                }))
            }
            NetworkGenesis::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ChainConfig, Hash32};

    use super::*;
    use crate::run::PresetName;

    fn resolve(words: &[&str]) -> Result<ChainChoice, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = ChainFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        flags.resolve()
    }

    /// The digest hoodi publishes for its genesis state.
    fn hoodi_checksum() -> Hash32 {
        let NetworkGenesis::Published(checksum) =
            Network::built_in(BuiltInNetwork::Hoodi).unwrap().genesis
        else {
            panic!("hoodi publishes a digest");
        };
        checksum
    }

    #[test]
    fn mainnet_starts_from_its_embedded_genesis() {
        let choice = resolve(&[]).unwrap();
        assert_eq!(choice.network.preset, PresetName::Mainnet);
        assert!(matches!(
            choice.anchor,
            Some(AnchorSource::Genesis(GenesisState::Embedded(_)))
        ));
        assert_eq!(choice.history, HistorySettings::default());
    }

    #[test]
    fn a_published_genesis_downloads_from_the_named_server() {
        // Without a server, hoodi has no anchor to start from.
        assert_eq!(resolve(&["--network", "hoodi"]).unwrap().anchor, None);

        // The genesis server gets its own timeout.
        let choice = resolve(&[
            "--network",
            "hoodi",
            "--genesis-state-url",
            "http://10.0.0.3:5052",
            "--genesis-state-url-timeout",
            "60",
        ])
        .unwrap();
        assert_eq!(
            choice.anchor,
            Some(AnchorSource::Genesis(GenesisState::Download(
                GenesisDownload {
                    url: "http://10.0.0.3:5052".to_owned(),
                    checksum: hoodi_checksum(),
                    timeout: Duration::from_secs(60),
                }
            )))
        );
    }

    #[test]
    fn an_archive_checkpoint_rebuilds_from_the_checkpoint_server_genesis() {
        // The checkpoint server also serves genesis, under the checkpoint timeout.
        let choice = resolve(&[
            "--network",
            "hoodi",
            "--checkpoint-sync-url",
            "http://10.0.0.2:5052",
            "--checkpoint-sync-url-timeout",
            "30",
            "--archive",
        ])
        .unwrap();
        let timeout = Duration::from_secs(30);
        assert_eq!(
            choice.anchor,
            Some(AnchorSource::Url {
                url: "http://10.0.0.2:5052".to_owned(),
                timeout,
            })
        );
        assert_eq!(
            choice.history.genesis,
            Some(GenesisState::Download(GenesisDownload {
                url: "http://10.0.0.2:5052".to_owned(),
                checksum: hoodi_checksum(),
                timeout,
            }))
        );
    }

    #[test]
    fn checkpoint_files_keep_genesis_only_for_an_archive() {
        let pruned =
            resolve(&["--checkpoint-state", "s.ssz", "--checkpoint-block", "b.ssz"]).unwrap();
        assert_eq!(
            pruned.anchor,
            Some(AnchorSource::Checkpoint {
                state: "s.ssz".into(),
                block: "b.ssz".into(),
            })
        );
        assert_eq!(pruned.history.genesis, None);

        // An archive takes the network's embedded genesis; a given file wins over it.
        let archive = resolve(&[
            "--archive",
            "--checkpoint-state",
            "s.ssz",
            "--checkpoint-block",
            "b.ssz",
        ])
        .unwrap();
        assert!(matches!(
            archive.history.genesis,
            Some(GenesisState::Embedded(_))
        ));
        let given = resolve(&[
            "--genesis-state",
            "g.ssz",
            "--checkpoint-sync-url",
            "http://10.0.0.2:5052",
        ])
        .unwrap();
        assert_eq!(
            given.history.genesis,
            Some(GenesisState::File("g.ssz".into()))
        );
    }

    #[test]
    fn trust_flags_reach_the_history_settings() {
        let root = "0x8584188b86a9296932785cc2827b925f9deebacce6d72ad8d53171fa046b43d9";
        let checkpoint = format!("{root}:9544");
        let choice = resolve(&[
            "--network",
            "minimal",
            "--snapshot-interval",
            "64",
            "--weak-subjectivity-checkpoint",
            &checkpoint,
            "--allow-insecure-genesis-sync",
            "--ignore-ws-check",
        ])
        .unwrap();
        assert_eq!(choice.network.chain, ChainConfig::minimal());
        assert_eq!(
            choice.history,
            HistorySettings {
                mode: StorageMode::Archive(SnapshotInterval::new(64).unwrap()),
                weak_subjectivity: Some(checkpoint.parse().unwrap()),
                genesis: None,
                allow_insecure_genesis_sync: true,
                ignore_ws_check: true,
            }
        );
    }

    #[test]
    fn conflicting_sources_are_refused() {
        assert!(matches!(
            resolve(&["--network", "sepolia", "--testnet-dir", "/devnet"]),
            Err(CliError::ConflictingNetworks)
        ));
        assert!(matches!(
            resolve(&["--checkpoint-state", "s.ssz"]),
            Err(CliError::ConflictingAnchors)
        ));
        assert!(matches!(
            resolve(&[
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
            resolve(&["--network", "goerli"]),
            Err(CliError::InvalidValue {
                flag: "--network",
                ..
            })
        ));
    }
}
