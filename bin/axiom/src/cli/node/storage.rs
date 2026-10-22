//! Where the node keeps its data, and the upkeep the database gets.

use std::path::PathBuf;

use axiom_node::{DatabaseSettings, SidecarPruning};

use crate::cli::{CliError, arguments::Arguments};

/// The usage lines of the storage flags.
pub(crate) const STORAGE_USAGE: &str = "\
    --datadir <DIR>              database directory [default: in memory]
    --purge-db                   delete the chain database first, after typing confirm
    --purge-db-force             delete the chain database first, without asking
    --compact-db                 compact the database at startup
    --auto-compact-db <BOOL>     compact the database as it runs [default: true]
    --prune-blobs <BOOL>         delete sidecars past their retention window [default: true]
    --epochs-per-blob-prune <EPOCHS>
                                 epochs between sidecar pruning rounds [default: 256]
    --blob-prune-margin-epochs <EPOCHS>
                                 epochs of sidecars kept past the window [default: 0]
";

/// How the chain database is deleted before the node starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purge {
    /// After the operator types the confirmation word at a terminal.
    Confirmed,
    /// At once.
    Forced,
}

/// The storage flags as given.
#[derive(Debug, Default)]
pub(crate) struct StorageFlags {
    /// The database directory.
    pub(crate) datadir: Option<PathBuf>,
    /// Whether to purge after confirmation.
    purge: bool,
    /// Whether to purge at once.
    purge_force: bool,
    /// Whether to compact at startup.
    compact: bool,
    /// Whether to compact as the node runs.
    auto_compact: Option<bool>,
    /// Whether expired sidecars are deleted.
    prune_blobs: Option<bool>,
    /// Epochs between pruning rounds.
    epochs_per_blob_prune: Option<u64>,
    /// Epochs kept past the window.
    blob_prune_margin_epochs: Option<u64>,
}

/// What the storage flags resolve to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StorageChoice {
    /// The database directory.
    pub(crate) datadir: Option<PathBuf>,
    /// How the database is deleted first, if it is.
    pub(crate) purge: Option<Purge>,
    /// Upkeep of the store.
    pub(crate) database: DatabaseSettings,
    /// When expired sidecars leave the disk.
    pub(crate) pruning: SidecarPruning,
}

impl StorageFlags {
    /// Takes a storage flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--datadir" => self.datadir = Some(words.path("--datadir")?),
            "--purge-db" => self.purge = true,
            "--purge-db-force" => self.purge_force = true,
            "--compact-db" => self.compact = true,
            "--auto-compact-db" => self.auto_compact = Some(words.boolean("--auto-compact-db")?),
            "--prune-blobs" => self.prune_blobs = Some(words.boolean("--prune-blobs")?),
            "--epochs-per-blob-prune" => {
                self.epochs_per_blob_prune = Some(words.parsed("--epochs-per-blob-prune")?);
            }
            "--blob-prune-margin-epochs" => {
                self.blob_prune_margin_epochs = Some(words.parsed("--blob-prune-margin-epochs")?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The data directory, the purge to run first, and the database upkeep.
    pub(crate) fn resolve(self) -> StorageChoice {
        let defaults = SidecarPruning::default();
        let purge = if self.purge_force {
            Some(Purge::Forced)
        } else {
            self.purge.then_some(Purge::Confirmed)
        };
        StorageChoice {
            datadir: self.datadir,
            purge,
            database: DatabaseSettings {
                auto_compact: self.auto_compact.unwrap_or(true),
                compact_on_start: self.compact,
            },
            pruning: SidecarPruning {
                enabled: self.prune_blobs.unwrap_or(defaults.enabled),
                interval_epochs: self
                    .epochs_per_blob_prune
                    .unwrap_or(defaults.interval_epochs),
                margin_epochs: self
                    .blob_prune_margin_epochs
                    .unwrap_or(defaults.margin_epochs),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(words: &[&str]) -> Result<StorageChoice, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = StorageFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        Ok(flags.resolve())
    }

    #[test]
    fn defaults_keep_compacting_and_prune_every_256_epochs() {
        assert_eq!(resolve(&[]).unwrap().pruning.interval_epochs, 256);
        assert_eq!(
            resolve(&[]).unwrap(),
            StorageChoice {
                datadir: None,
                purge: None,
                database: DatabaseSettings::default(),
                pruning: SidecarPruning::default(),
            }
        );
    }

    #[test]
    fn every_storage_flag_reaches_the_choice() {
        let choice = resolve(&[
            "--datadir",
            "/data",
            "--purge-db",
            "--compact-db",
            "--auto-compact-db",
            "false",
            "--prune-blobs",
            "false",
            "--epochs-per-blob-prune",
            "256",
            "--blob-prune-margin-epochs",
            "16",
        ])
        .unwrap();
        assert_eq!(
            choice,
            StorageChoice {
                datadir: Some("/data".into()),
                purge: Some(Purge::Confirmed),
                database: DatabaseSettings {
                    auto_compact: false,
                    compact_on_start: true,
                },
                pruning: SidecarPruning {
                    enabled: false,
                    interval_epochs: 256,
                    margin_epochs: 16,
                },
            }
        );
    }

    #[test]
    fn forcing_wins_over_asking() {
        let choice = resolve(&["--purge-db", "--purge-db-force"]).unwrap();
        assert_eq!(choice.purge, Some(Purge::Forced));
    }
}
