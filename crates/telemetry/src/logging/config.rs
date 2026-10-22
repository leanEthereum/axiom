//! What to log and how, and the method that installs it.

use std::io::{self, IsTerminal};

use tracing::{Subscriber, subscriber};
use tracing_subscriber::{
    Layer,
    filter::{ParseError, Targets},
    fmt::{Layer as FmtLayer, MakeWriter},
    layer::SubscriberExt,
    registry,
};

use crate::logging::{LogError, LogFormat, json::JsonFormat};

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
}

impl Default for LogConfig {
    fn default() -> Self {
        // Info shows lifecycle events without per-message noise.
        Self {
            filter: "info".to_owned(),
            format: LogFormat::default(),
        }
    }
}

impl LogConfig {
    /// Installs the process-wide logger, writing to standard error.
    ///
    /// Colours are used only when standard error is a terminal.
    ///
    /// # Errors
    ///
    /// Fails when the filter does not parse or a global subscriber already exists.
    pub fn init(&self) -> Result<(), LogError> {
        // Escape codes in a file or a pipe would be noise, so colour only a terminal.
        let ansi = io::stderr().is_terminal();
        let built = self.build(io::stderr, ansi)?;
        // The global default can be set once per process.
        subscriber::set_global_default(built).map_err(|_| LogError::AlreadyInstalled)
    }

    /// A subscriber writing to any sink, without colours, and not installed.
    ///
    /// Tests and embedders scope it to a thread instead of the whole process.
    ///
    /// # Errors
    ///
    /// Fails when the filter does not parse.
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

        // Phase 2: one formatting layer, shaped by the chosen layout.
        let layer = FmtLayer::default().with_writer(writer).with_ansi(ansi);

        // Phase 3: stack the filtered layer on a span registry.
        // Each layout yields a different type, so each is boxed to one.
        let built: BoxedSubscriber = match self.format {
            LogFormat::Pretty => Box::new(registry().with(layer.pretty().with_filter(targets))),
            LogFormat::Compact => Box::new(registry().with(layer.compact().with_filter(targets))),
            // A collector parses the lines, so JSON never carries escape codes.
            LogFormat::Json => Box::new(
                registry().with(
                    layer
                        .with_ansi(false)
                        .event_format(JsonFormat)
                        .with_filter(targets),
                ),
            ),
        };
        Ok(built)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_filters_are_reported() {
        // "loud" is not a level name.
        let config = LogConfig {
            filter: "axiom=loud".to_owned(),
            format: LogFormat::Compact,
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
}
