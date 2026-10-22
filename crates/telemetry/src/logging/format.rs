//! The layout of each log line.

use tracing_subscriber::{
    Layer, Registry,
    fmt::{Layer as FmtLayer, MakeWriter},
    layer::Filter,
};

use crate::logging::json::JsonFormat;

/// One filtered, formatted output of the logger, with its concrete type erased.
pub(crate) type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

/// How each log event is laid out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LogFormat {
    /// Multi-line, indented output for a developer at a terminal.
    Pretty,

    /// One line per event, for operators reading a terminal or a journal.
    #[default]
    Compact,

    /// One JSON object per line, for log collectors.
    Json,
}

impl LogFormat {
    /// An output in this layout, writing the events a filter lets through.
    pub(crate) fn layer<W, F>(self, writer: W, ansi: bool, filter: F) -> BoxedLayer
    where
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
        F: Filter<Registry> + Send + Sync + 'static,
    {
        let layer = FmtLayer::default().with_writer(writer).with_ansi(ansi);
        // Each layout yields a different type, so each is boxed to one.
        match self {
            Self::Pretty => Box::new(layer.pretty().with_filter(filter)),
            Self::Compact => Box::new(layer.compact().with_filter(filter)),
            // A collector parses the lines, so JSON never carries escape codes.
            Self::Json => Box::new(
                layer
                    .with_ansi(false)
                    .event_format(JsonFormat)
                    .with_filter(filter),
            ),
        }
    }
}
