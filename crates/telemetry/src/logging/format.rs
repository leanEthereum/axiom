//! The layout of each log line.

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
