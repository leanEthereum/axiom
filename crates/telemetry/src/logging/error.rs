//! Errors raised while installing the logger.

use std::{error::Error, fmt};

/// A logger that could not be installed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogError {
    /// The filter directives do not parse; the parser's message is kept.
    InvalidFilter(String),

    /// Another global subscriber is already installed in this process.
    AlreadyInstalled,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFilter(reason) => write!(f, "invalid log filter: {reason}"),
            Self::AlreadyInstalled => f.write_str("a global log subscriber is already installed"),
        }
    }
}

impl Error for LogError {}
