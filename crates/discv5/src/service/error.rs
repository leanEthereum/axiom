//! Reasons the service refuses to start.

use thiserror::Error;

/// A service configuration that cannot work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ServiceError {
    /// The local record is signed by another key than the one given.
    #[error("local record does not belong to the local key")]
    KeyMismatch,
}
