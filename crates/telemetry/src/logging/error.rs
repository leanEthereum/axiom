//! Errors raised while installing the logger.

use thiserror::Error;

/// A logger that could not be installed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LogError {
    /// The filter directives do not parse; the parser's message is kept.
    #[error("invalid log filter: {0}")]
    InvalidFilter(String),

    /// Another global subscriber is already installed in this process.
    #[error("a global log subscriber is already installed")]
    AlreadyInstalled,
}
