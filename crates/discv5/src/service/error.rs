//! Reasons the service refuses to start.

use std::{error::Error, fmt};

/// A service configuration that cannot work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The local record is signed by another key than the one given.
    KeyMismatch,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMismatch => f.write_str("local record does not belong to the local key"),
        }
    }
}

impl Error for ServiceError {}
