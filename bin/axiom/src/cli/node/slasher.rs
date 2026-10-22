//! The slasher: whether it runs, its history's layout, where it lives, and how often it looks.

use std::{path::PathBuf, time::Duration};

use axiom_node::SlasherSetup;
use axiom_slasher::SlasherConfig;

use crate::cli::{CliError, arguments::Arguments};

/// The usage lines of the slasher flags.
pub(crate) const SLASHER_USAGE: &str = "\
    --slasher                    detect slashable votes and proposals, and pool the evidence
    --slasher-history <EPOCHS>   epochs of votes the slasher keeps [default: 4096]
    --slasher-chunk-epochs <N>   epochs per span chunk on disk [default: 16]
    --slasher-chunk-validators <N>
                                 validators per span chunk on disk [default: 1024]
    --slasher-dir <DIR>          the slasher's database directory [default: DATADIR/slasher]
    --slasher-update-period <SECONDS>
                                 time between slasher passes [default: one slot]
";

/// The slasher flags as given.
#[derive(Debug, Default)]
pub(crate) struct SlasherFlags {
    /// Whether the slasher runs.
    enabled: bool,
    /// Epochs of history.
    history: Option<u64>,
    /// Epochs per span chunk.
    chunk_epochs: Option<u64>,
    /// Validators per span chunk.
    chunk_validators: Option<u64>,
    /// The database directory.
    directory: Option<PathBuf>,
    /// Seconds between passes.
    update_period: Option<u64>,
}

impl SlasherFlags {
    /// Takes a slasher flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--slasher" => self.enabled = true,
            "--slasher-history" => self.history = Some(words.parsed("--slasher-history")?),
            "--slasher-chunk-epochs" => {
                self.chunk_epochs = Some(words.parsed("--slasher-chunk-epochs")?);
            }
            "--slasher-chunk-validators" => {
                self.chunk_validators = Some(words.parsed("--slasher-chunk-validators")?);
            }
            "--slasher-dir" => self.directory = Some(words.path("--slasher-dir")?),
            "--slasher-update-period" => {
                self.update_period = Some(words.parsed("--slasher-update-period")?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The layout with defaults filled in, or none when the slasher is off, and where it runs.
    pub(crate) fn resolve(self) -> Result<(Option<SlasherConfig>, SlasherSetup), CliError> {
        if !self.enabled {
            let settings = [
                ("--slasher-history", self.history.is_some()),
                ("--slasher-chunk-epochs", self.chunk_epochs.is_some()),
                (
                    "--slasher-chunk-validators",
                    self.chunk_validators.is_some(),
                ),
                ("--slasher-dir", self.directory.is_some()),
                ("--slasher-update-period", self.update_period.is_some()),
            ];
            return match settings.iter().find(|(_, given)| *given) {
                Some((flag, _)) => Err(CliError::SlasherDisabled(flag)),
                None => Ok((None, SlasherSetup::default())),
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
        let setup = SlasherSetup {
            directory: self.directory,
            update_period: self.update_period.map(Duration::from_secs),
        };
        Ok((Some(config), setup))
    }
}

#[cfg(test)]
mod tests {
    use axiom_slasher::LayoutError;

    use super::*;

    fn resolve(words: &[&str]) -> Result<(Option<SlasherConfig>, SlasherSetup), CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = SlasherFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        flags.resolve()
    }

    #[test]
    fn the_slasher_flags_set_its_layout_and_place() {
        // History of 1024 epochs in chunks of 8 by 512 validators, a pass every 36 seconds.
        let (config, setup) = resolve(&[
            "--slasher",
            "--slasher-history",
            "1024",
            "--slasher-chunk-epochs",
            "8",
            "--slasher-chunk-validators",
            "512",
            "--slasher-dir",
            "/slasher",
            "--slasher-update-period",
            "36",
        ])
        .unwrap();
        assert_eq!(
            config,
            Some(SlasherConfig {
                history_length: 1024,
                chunk_size: 8,
                validator_chunk_size: 512,
                ..SlasherConfig::default()
            })
        );
        assert_eq!(
            setup,
            SlasherSetup {
                directory: Some("/slasher".into()),
                update_period: Some(Duration::from_secs(36)),
            }
        );
        // The bare flag takes every default.
        assert_eq!(
            resolve(&["--slasher"]).unwrap(),
            (Some(SlasherConfig::default()), SlasherSetup::default())
        );
    }

    #[test]
    fn slasher_settings_need_the_slasher_and_a_valid_layout() {
        assert!(matches!(
            resolve(&["--slasher-dir", "/slasher"]),
            Err(CliError::SlasherDisabled("--slasher-dir"))
        ));
        // 100 epochs do not split into chunks of 16.
        assert!(matches!(
            resolve(&["--slasher", "--slasher-history", "100"]),
            Err(CliError::Slasher(LayoutError::Indivisible {
                history: 100,
                chunk: 16
            }))
        ));
    }
}
