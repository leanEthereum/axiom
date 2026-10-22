//! Errors raised while installing the logger.

use std::{
    io,
    path::{Path, PathBuf},
};

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

    /// The log file, or the directory meant to hold it, cannot be opened.
    #[error("cannot open log file {path:?}: {reason}")]
    CannotOpen {
        /// The file or directory that failed.
        path: PathBuf,
        /// The operating system's message.
        reason: String,
    },

    /// Another global subscriber is already installed in this process.
    #[error("a global log subscriber is already installed")]
    AlreadyInstalled,
}

impl LogError {
    /// The failure to open a path, keeping the message so the error stays comparable.
    pub(crate) fn cannot_open(path: &Path, error: &io::Error) -> Self {
        Self::CannotOpen {
            path: path.to_owned(),
            reason: error.to_string(),
        }
    }
}
