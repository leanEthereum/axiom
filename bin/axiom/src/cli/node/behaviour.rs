//! How the chain thread behaves, when the node stops, and what it writes out at startup.

use std::path::PathBuf;

use axiom_node::{ChainSettings, SidecarPruning};

use crate::cli::{CliError, arguments::Arguments};

/// The usage lines of the behaviour flags.
pub(crate) const BEHAVIOUR_USAGE: &str = "\
    --max-skip-slots <N|none>    most slots a vote may lie past its block [default: none]
    --enable-fast-confirmation   name the engine's safe block by the fast confirmation rule
    --disable-light-client-server
                                 derive and serve no light client data
    --shutdown-after-sync        stop once the head reaches the wall clock
    --dump-config <FILE>         write the resolved node configuration as JSON, then run
    --dump-chain-config <FILE>   write the chain configuration as JSON, then run
";

/// The behaviour flags as given.
#[derive(Debug, Default)]
pub(crate) struct BehaviourFlags {
    /// Most slots a vote may skip, when bounded.
    max_skip_slots: Option<u64>,
    /// Whether the fast confirmation rule runs.
    fast_confirmation: bool,
    /// Whether light client data is off.
    no_light_client_server: bool,
    /// Whether the node stops once synced.
    pub(crate) shutdown_after_sync: bool,
    /// Where to write the node configuration.
    pub(crate) dump_config: Option<PathBuf>,
    /// Where to write the chain configuration.
    pub(crate) dump_chain_config: Option<PathBuf>,
}

impl BehaviourFlags {
    /// Takes a behaviour flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--max-skip-slots" => {
                let value = words.value("--max-skip-slots")?;
                // The word none lifts the bound, as when the flag is absent.
                self.max_skip_slots = match value.as_str() {
                    "none" => None,
                    _ => Some(value.parse().map_err(|_| CliError::InvalidValue {
                        flag: "--max-skip-slots",
                        value,
                    })?),
                };
            }
            "--enable-fast-confirmation" => self.fast_confirmation = true,
            "--disable-light-client-server" => self.no_light_client_server = true,
            "--shutdown-after-sync" => self.shutdown_after_sync = true,
            "--dump-config" => self.dump_config = Some(words.path("--dump-config")?),
            "--dump-chain-config" => {
                self.dump_chain_config = Some(words.path("--dump-chain-config")?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The chain thread's settings, with the sidecar pruning the storage flags chose.
    pub(crate) const fn chain_settings(&self, sidecar_pruning: SidecarPruning) -> ChainSettings {
        ChainSettings {
            max_skip_slots: self.max_skip_slots,
            fast_confirmation: self.fast_confirmation,
            light_client_server: !self.no_light_client_server,
            sidecar_pruning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(words: &[&str]) -> Result<BehaviourFlags, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = BehaviourFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        Ok(flags)
    }

    #[test]
    fn chain_flags_reach_the_chain_settings() {
        let pruning = SidecarPruning::default();
        let settings = flags(&[
            "--max-skip-slots",
            "700",
            "--enable-fast-confirmation",
            "--disable-light-client-server",
        ])
        .unwrap()
        .chain_settings(pruning);
        assert_eq!(
            settings,
            ChainSettings {
                max_skip_slots: Some(700),
                fast_confirmation: true,
                light_client_server: false,
                sidecar_pruning: pruning,
            }
        );
        // No flags keep the chain's defaults; none lifts a bound given before it.
        let unbounded = flags(&["--max-skip-slots", "5", "--max-skip-slots", "none"]).unwrap();
        assert_eq!(unbounded.chain_settings(pruning), ChainSettings::default());
    }

    #[test]
    fn a_skip_bound_is_a_number_or_none() {
        assert!(matches!(
            flags(&["--max-skip-slots", "many"]),
            Err(CliError::InvalidValue {
                flag: "--max-skip-slots",
                ..
            })
        ));
    }
}
