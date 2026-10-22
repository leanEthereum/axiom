//! The logging flags every long-running command shares: the terminal, and a rotating file.

use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use axiom_telemetry::{LogConfig, LogFile, LogFormat};
use tracing::level_filters::LevelFilter;

use crate::cli::{Cli, CliError, arguments::Arguments};

/// The usage lines of the logging flags.
pub(crate) const LOG_USAGE: &str = "\
    --log <FILTER>               log filter, such as info,axiom_node=debug [default: info]
    --log-format <FORMAT>        compact, pretty, or json [default: compact]
    --logfile-dir <DIR>          directory of the log files [default: DATADIR/logs]
    --logfile-debug-level <LEVEL>
                                 error, warn, info, debug, or trace [default: debug]
    --logfile-format <FORMAT>    default, compact, pretty, or json [default: as --log-format]
    --logfile-max-size <MB>      size at which a log file rotates; 0 disables files [default: 200]
    --logfile-max-number <N>     log files kept; 0 disables files [default: 10]
    --logfile-compress           gzip the rotated log files
    --logfile-no-restricted-perms
                                 let every local user read the log files
    --logfile-color              keep colour codes in the log files
";

/// Bytes in the megabyte the size flag counts in.
const MEGABYTE: u64 = 1 << 20;

/// The logging flags as given.
#[derive(Debug, Default)]
pub(crate) struct LogFlags {
    /// The terminal's filter directives.
    filter: Option<String>,
    /// The terminal's layout.
    format: Option<LogFormat>,
    /// The log files' directory.
    file_directory: Option<PathBuf>,
    /// The log files' level.
    file_level: Option<LevelFilter>,
    /// The log files' layout.
    file_format: Option<LogFormat>,
    /// The size a log file rotates at, in megabytes.
    file_max_size: Option<u64>,
    /// How many log files are kept.
    file_max_number: Option<u64>,
    /// Whether rotated files are compressed.
    compress: bool,
    /// Whether every local user may read the files.
    unrestricted: bool,
    /// Whether the files keep colour codes.
    color: bool,
}

impl LogFlags {
    /// Takes a logging flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        self.read_with(flag, |name| words.value(name))
    }

    /// Takes a logging flag whose value, if it needs one, comes from a supplier.
    ///
    /// A command that reads its words its own way hands over its own supplier.
    pub(crate) fn read_with(
        &mut self,
        flag: &str,
        mut value: impl FnMut(&'static str) -> Result<String, CliError>,
    ) -> Result<bool, CliError> {
        match flag {
            "--log" => self.filter = Some(value("--log")?),
            "--log-format" => {
                self.format = Some(Self::format("--log-format", value("--log-format")?)?);
            }
            "--logfile-dir" => self.file_directory = Some(value("--logfile-dir")?.into()),
            "--logfile-debug-level" => {
                self.file_level = Some(Self::level(value("--logfile-debug-level")?)?);
            }
            "--logfile-format" => {
                let text = value("--logfile-format")?;
                self.file_format = Some(Self::format("--logfile-format", text)?);
            }
            "--logfile-max-size" => {
                let text = value("--logfile-max-size")?;
                self.file_max_size = Some(Cli::parsed("--logfile-max-size", text)?);
            }
            "--logfile-max-number" => {
                let text = value("--logfile-max-number")?;
                self.file_max_number = Some(Cli::parsed("--logfile-max-number", text)?);
            }
            "--logfile-compress" => self.compress = true,
            "--logfile-no-restricted-perms" => self.unrestricted = true,
            "--logfile-color" => self.color = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The logger, writing files named after a role into the given or the default directory.
    ///
    /// No directory, a zero size, or a zero count keeps the log on the terminal only.
    pub(crate) fn resolve(self, default_directory: Option<PathBuf>, role: &str) -> LogConfig {
        let format = self.format.unwrap_or_default();
        let file = self
            .file_directory
            .or(default_directory)
            .and_then(|directory| {
                let megabytes = self
                    .file_max_size
                    .map_or(Some(LogFile::DEFAULT_MAX_SIZE), |size| {
                        NonZeroU64::new(size.saturating_mul(MEGABYTE))
                    })?;
                let count = self
                    .file_max_number
                    .map_or(Some(LogFile::DEFAULT_MAX_FILES), |count| {
                        NonZeroUsize::new(usize::try_from(count).unwrap_or(usize::MAX))
                    })?;
                Some(LogFile {
                    level: self.file_level.unwrap_or(LevelFilter::DEBUG),
                    format: self.file_format.unwrap_or(format),
                    max_size: megabytes,
                    max_files: count,
                    compress: self.compress,
                    restricted: !self.unrestricted,
                    color: self.color,
                    ..LogFile::new(directory, role.to_owned())
                })
            });
        LogConfig {
            filter: self.filter.unwrap_or_else(|| "info".to_owned()),
            format,
            file,
        }
    }

    /// A layout name; the file flag also takes the word default, for the compact layout.
    pub(crate) fn format(flag: &'static str, value: String) -> Result<LogFormat, CliError> {
        match value.to_ascii_lowercase().as_str() {
            "compact" | "default" => Ok(LogFormat::Compact),
            "pretty" => Ok(LogFormat::Pretty),
            "json" => Ok(LogFormat::Json),
            _ => Err(CliError::InvalidValue { flag, value }),
        }
    }

    /// A level name.
    fn level(value: String) -> Result<LevelFilter, CliError> {
        match value.as_str() {
            "error" => Ok(LevelFilter::ERROR),
            "warn" => Ok(LevelFilter::WARN),
            "info" => Ok(LevelFilter::INFO),
            "debug" => Ok(LevelFilter::DEBUG),
            "trace" => Ok(LevelFilter::TRACE),
            _ => Err(CliError::InvalidValue {
                flag: "--logfile-debug-level",
                value,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(words: &[&str]) -> LogFlags {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = LogFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words).unwrap(), "{flag}");
        }
        flags
    }

    #[test]
    fn a_data_directory_alone_keeps_the_default_files() {
        let config = flags(&[]).resolve(Some("data/logs".into()), "beacon");
        assert_eq!(
            config,
            LogConfig {
                filter: "info".to_owned(),
                format: LogFormat::Compact,
                file: Some(LogFile::new("data/logs".into(), "beacon".to_owned())),
            }
        );
        // Without any directory, the log stays on the terminal.
        assert_eq!(flags(&[]).resolve(None, "beacon").file, None);
    }

    #[test]
    fn every_file_flag_reaches_the_file() {
        let config = flags(&[
            "--log-format",
            "json",
            "--logfile-dir",
            "/var/log/axiom",
            "--logfile-debug-level",
            "trace",
            "--logfile-format",
            "DEFAULT",
            "--logfile-max-size",
            "50",
            "--logfile-max-number",
            "3",
            "--logfile-compress",
            "--logfile-no-restricted-perms",
            "--logfile-color",
        ])
        .resolve(Some("ignored".into()), "validator");

        // 50 MB is 50 * 2^20 bytes; the terminal's JSON does not reach the file.
        assert_eq!(
            config.file,
            Some(LogFile {
                directory: "/var/log/axiom".into(),
                name: "validator".to_owned(),
                level: LevelFilter::TRACE,
                format: LogFormat::Compact,
                max_size: NonZeroU64::new(52_428_800).unwrap(),
                max_files: NonZeroUsize::new(3).unwrap(),
                compress: true,
                restricted: false,
                color: true,
            })
        );
        assert_eq!(config.format, LogFormat::Json);
    }

    #[test]
    fn the_file_format_follows_the_terminal_unless_given() {
        let config = flags(&["--log-format", "pretty"]).resolve(Some("logs".into()), "beacon");
        assert_eq!(config.file.map(|file| file.format), Some(LogFormat::Pretty));
    }

    #[test]
    fn a_zero_size_or_count_disables_the_files() {
        let sized = flags(&["--logfile-max-size", "0"]).resolve(Some("logs".into()), "beacon");
        assert_eq!(sized.file, None);
        let counted = flags(&["--logfile-max-number", "0"]).resolve(Some("logs".into()), "beacon");
        assert_eq!(counted.file, None);
    }

    #[test]
    fn unknown_levels_and_formats_are_refused() {
        let mut words = Arguments::new(["loud".to_owned()].into_iter());
        assert!(matches!(
            LogFlags::default().read("--logfile-debug-level", &mut words),
            Err(CliError::InvalidValue {
                flag: "--logfile-debug-level",
                ..
            })
        ));
        assert!(matches!(
            LogFlags::format("--logfile-format", "xml".to_owned()),
            Err(CliError::InvalidValue {
                flag: "--logfile-format",
                ..
            })
        ));
    }
}
