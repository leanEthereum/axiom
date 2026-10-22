//! Watching validators, and pushing client stats to a remote collector.

use std::{fs, path::PathBuf, time::Duration};

use axiom_json::Data;
use axiom_node::{ClientStatsSettings, DEFAULT_PUSH_PERIOD, MonitorSettings};
use axiom_types::BlsPubkey;

use crate::cli::{CliError, arguments::Arguments};

/// The usage lines of the monitoring flags.
pub(crate) const MONITORING_USAGE: &str = "\
    --validator-monitor-auto     watch every validator the node's validator clients subscribe for
    --validator-monitor-pubkeys <KEYS>
                                 comma-separated validator keys to watch
    --validator-monitor-file <FILE>
                                 a file of comma-separated validator keys to watch
    --validator-monitor-individual-tracking-threshold <N>
                                 watched validators past which only totals are kept [default: 64]
    --monitoring-endpoint <URL>  push client stats to this collector, such as beaconcha.in's
    --monitoring-endpoint-period <SECONDS>
                                 seconds between client stats pushes [default: 60]
";

/// The monitoring flags as given.
#[derive(Debug, Default)]
pub(crate) struct MonitoringFlags {
    /// Whether subscribed validators are watched.
    auto: bool,
    /// Keys named on the command line.
    pubkeys: Vec<BlsPubkey>,
    /// A file of keys.
    file: Option<PathBuf>,
    /// Watched validators past which only totals are kept.
    threshold: Option<usize>,
    /// The client stats collector.
    endpoint: Option<String>,
    /// Seconds between pushes.
    period: Option<u64>,
}

impl MonitoringFlags {
    /// Takes a monitoring flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--validator-monitor-auto" => self.auto = true,
            "--validator-monitor-pubkeys" => {
                let text = words.value("--validator-monitor-pubkeys")?;
                self.pubkeys
                    .extend(Self::keys("--validator-monitor-pubkeys", &text)?);
            }
            "--validator-monitor-file" => {
                self.file = Some(words.path("--validator-monitor-file")?);
            }
            "--validator-monitor-individual-tracking-threshold" => {
                self.threshold =
                    Some(words.parsed("--validator-monitor-individual-tracking-threshold")?);
            }
            "--monitoring-endpoint" => {
                self.endpoint = Some(words.value("--monitoring-endpoint")?);
            }
            "--monitoring-endpoint-period" => {
                self.period = Some(words.parsed("--monitoring-endpoint-period")?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The monitor's settings, with the keys of the file, and the client stats push.
    ///
    /// # Errors
    ///
    /// Fails when the key file is unreadable or holds a malformed key.
    /// Fails when a push period is given without an endpoint, or is zero.
    pub(crate) fn resolve(
        self,
    ) -> Result<(MonitorSettings, Option<ClientStatsSettings>), CliError> {
        let mut pubkeys = self.pubkeys;
        if let Some(path) = &self.file {
            let text = fs::read_to_string(path).map_err(|_| CliError::InvalidValue {
                flag: "--validator-monitor-file",
                value: path.display().to_string(),
            })?;
            pubkeys.extend(Self::keys("--validator-monitor-file", &text)?);
        }
        let monitor = MonitorSettings {
            auto_register: self.auto,
            pubkeys,
            individual_tracking_threshold: self
                .threshold
                .unwrap_or_else(|| MonitorSettings::default().individual_tracking_threshold),
        };
        let stats = match (self.endpoint, self.period) {
            (None, None) => None,
            (None, Some(_)) => {
                return Err(CliError::Requires {
                    flag: "--monitoring-endpoint-period",
                    needs: "--monitoring-endpoint",
                });
            }
            (Some(_), Some(0)) => {
                return Err(CliError::InvalidValue {
                    flag: "--monitoring-endpoint-period",
                    value: "0".to_owned(),
                });
            }
            (Some(endpoint), period) => Some(ClientStatsSettings {
                endpoint,
                period: period.map_or(DEFAULT_PUSH_PERIOD, Duration::from_secs),
            }),
        };
        Ok((monitor, stats))
    }

    /// Comma-separated keys, blanks and line breaks around each ignored.
    fn keys(flag: &'static str, text: &str) -> Result<Vec<BlsPubkey>, CliError> {
        text.split(',')
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(|key| {
                <[u8; 48]>::from_data(key)
                    .map(BlsPubkey)
                    .map_err(|_| CliError::InvalidValue {
                        flag,
                        value: key.to_owned(),
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    fn flags(words: &[&str]) -> Result<MonitoringFlags, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = MonitoringFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        Ok(flags)
    }

    #[test]
    fn keys_come_from_the_flag_and_the_file() {
        // Fixture state: key 0x11.. on the command line, 0x22.. and 0x33.. in a file.
        let file = env::temp_dir().join(format!("axiom-monitor-keys-{}", process::id()));
        let key = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(48));
        fs::write(&file, format!("{},\n {}\n", key(0x22), key(0x33))).unwrap();
        let given = flags(&[
            "--validator-monitor-auto",
            "--validator-monitor-pubkeys",
            &key(0x11),
            "--validator-monitor-file",
            file.to_str().unwrap(),
            "--validator-monitor-individual-tracking-threshold",
            "8",
        ])
        .unwrap();
        let (monitor, stats) = given.resolve().unwrap();
        let _removed = fs::remove_file(&file);
        assert_eq!(
            monitor,
            MonitorSettings {
                auto_register: true,
                pubkeys: vec![
                    BlsPubkey([0x11; 48]),
                    BlsPubkey([0x22; 48]),
                    BlsPubkey([0x33; 48])
                ],
                individual_tracking_threshold: 8,
            }
        );
        assert_eq!(stats, None);
    }

    #[test]
    fn the_push_needs_an_endpoint_and_a_period_above_zero() {
        let (_, stats) = flags(&["--monitoring-endpoint", "http://collector/api"])
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(
            stats,
            Some(ClientStatsSettings {
                endpoint: "http://collector/api".to_owned(),
                period: Duration::from_secs(60),
            })
        );
        assert!(matches!(
            flags(&["--monitoring-endpoint-period", "30"])
                .unwrap()
                .resolve(),
            Err(CliError::Requires {
                flag: "--monitoring-endpoint-period",
                needs: "--monitoring-endpoint",
            })
        ));
        assert!(matches!(
            flags(&["--validator-monitor-pubkeys", "0x12"]),
            Err(CliError::InvalidValue {
                flag: "--validator-monitor-pubkeys",
                ..
            })
        ));
    }
}
