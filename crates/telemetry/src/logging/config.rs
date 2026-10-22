//! What to log and how, and the method that installs it.

use std::io::{self, IsTerminal};

use tracing::{Subscriber, subscriber};
use tracing_subscriber::{
    filter::{ParseError, Targets},
    fmt::MakeWriter,
    layer::SubscriberExt,
    registry,
};

use crate::logging::{LogError, LogFile, LogFormat};

/// A log subscriber with its concrete type erased, so every format shares one type.
type BoxedSubscriber = Box<dyn Subscriber + Send + Sync>;

/// Which events to log and how to lay them out.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogConfig {
    /// Comma-separated directives: a bare default level, then per-target levels.
    ///
    /// ```text
    ///     info,axiom_fork_choice=debug,axiom_http=warn
    /// ```
    pub filter: String,

    /// The layout of each line.
    pub format: LogFormat,

    /// A copy of the log kept on disk, with its own level and layout.
    pub file: Option<LogFile>,
}

impl Default for LogConfig {
    fn default() -> Self {
        // Info shows lifecycle events without per-message noise.
        Self {
            filter: "info".to_owned(),
            format: LogFormat::default(),
            file: None,
        }
    }
}

impl LogConfig {
    /// Installs the process-wide logger, writing to standard error and to the file if any.
    ///
    /// Colours are used on standard error only when it is a terminal.
    ///
    /// # Errors
    ///
    /// Fails when the filter does not parse, the file cannot be opened, or a logger exists.
    pub fn init(&self) -> Result<(), LogError> {
        // Escape codes in a file or a pipe would be noise, so colour only a terminal.
        let ansi = io::stderr().is_terminal();
        let built = self.build(io::stderr, ansi)?;
        // The global default can be set once per process.
        subscriber::set_global_default(built).map_err(|_| LogError::AlreadyInstalled)
    }

    /// A subscriber writing to any sink, without colours, and not installed.
    ///
    /// The file, if any, is opened and written as well.
    /// Tests and embedders scope it to a thread instead of the whole process.
    ///
    /// # Errors
    ///
    /// Fails when the filter does not parse or the file cannot be opened.
    pub fn subscriber<W>(&self, writer: W) -> Result<BoxedSubscriber, LogError>
    where
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        // Captured output is compared as text, so escape codes stay out.
        self.build(writer, false)
    }

    /// Builds the filtered, formatted subscriber.
    fn build<W>(&self, writer: W, ansi: bool) -> Result<BoxedSubscriber, LogError>
    where
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        // Phase 1: parse the directives into a per-target level table.
        let targets: Targets =
            self.filter
                .parse()
                .map_err(|error: ParseError| LogError::InvalidFilter {
                    filter: self.filter.clone(),
                    reason: error.to_string(),
                })?;

        // Phase 2: the sink's output, in its own layout.
        let mut layers = vec![self.format.layer(writer, ansi, targets)];

        // Phase 3: the file's output, with its own level and layout.
        // Each output filters on its own, so the file can keep detail the terminal hides.
        if let Some(file) = &self.file {
            layers.push(file.layer()?);
        }

        // Phase 4: stack the outputs on one span registry.
        Ok(Box::new(registry().with(layers)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        fs::{self, File},
        path::Path,
        process,
        sync::Arc,
    };

    use tracing::{debug, info};

    use super::*;

    /// Each line of a log file, with its leading timestamp dropped.
    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| line.split_once(' ').unwrap().1.trim_start().to_owned())
            .collect()
    }

    #[test]
    fn bad_filters_are_reported() {
        // "loud" is not a level name.
        let config = LogConfig {
            filter: "axiom=loud".to_owned(),
            format: LogFormat::Compact,
            file: None,
        };
        // The error carries the directives as written and the parser's reason.
        assert_eq!(
            config.subscriber(io::sink).err(),
            Some(LogError::InvalidFilter {
                filter: "axiom=loud".to_owned(),
                reason: "error parsing level filter: expected one of \"off\", \"error\", \
                         \"warn\", \"info\", \"debug\", \"trace\", or a number 0-5"
                    .to_owned(),
            })
        );
    }

    #[test]
    fn the_file_keeps_its_own_level() {
        // Fixture state: the terminal at info, the file at its default of debug.
        let directory = env::temp_dir().join(format!("axiom-log-layers-{}", process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let terminal = directory.join("terminal.txt");
        let config = LogConfig {
            filter: "info".to_owned(),
            format: LogFormat::Compact,
            file: Some(LogFile::new(directory.clone(), "beacon".to_owned())),
        };
        let sink = Arc::new(File::create(&terminal).unwrap());
        let built = config.subscriber(sink).unwrap();

        // One event below the terminal's level, one at it.
        subscriber::with_default(built, || {
            debug!("peer scored");
            info!("block imported");
        });

        // The terminal shows only the info line; the file shows both.
        let target = "axiom_telemetry::logging::config::tests";
        assert_eq!(lines(&terminal), [format!("INFO {target}: block imported")]);
        assert_eq!(
            lines(&directory.join("beacon.log")),
            [
                format!("DEBUG {target}: peer scored"),
                format!("INFO {target}: block imported"),
            ]
        );
        fs::remove_dir_all(&directory).unwrap();
    }
}
