//! Errors raised while installing the logger.

use thiserror::Error;

/// A logger that could not be installed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LogError {
    /// The filter directives do not parse.
    #[error("invalid log filter {filter:?}: {reason}")]
    InvalidFilter {
        /// The directives as configured.
        filter: String,
        /// The parser's message.
        reason: String,
    },

    /// Another global subscriber is already installed in this process.
    #[error("a global log subscriber is already installed")]
    AlreadyInstalled,
}
