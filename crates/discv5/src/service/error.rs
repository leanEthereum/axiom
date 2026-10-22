//! Reasons the service refuses to start.

use thiserror::Error;

use crate::NodeId;

/// A service configuration that cannot work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ServiceError {
    /// The local record is signed by another key than the one given.
    #[error("local record of node {record} does not belong to the local node {local}")]
    KeyMismatch {
        /// The node the record names.
        record: NodeId,
        /// The node the local key names.
        local: NodeId,
    },
}
