//! The two ways a gossip message fails validation.

use thiserror::Error;

/// Why a gossip message is not forwarded.
///
/// The reason is the spec's own wording, kept for logs and for matching vectors by eye.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GossipError {
    /// The message is dropped without penalizing its sender.
    #[error("ignore: {0}")]
    Ignore(&'static str),
    /// The message is invalid, and its sender is penalized.
    #[error("reject: {0}")]
    Reject(&'static str),
}
