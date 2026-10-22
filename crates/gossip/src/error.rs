//! The two ways a gossip message fails validation.

use std::{error::Error, fmt};

/// Why a gossip message is not forwarded.
///
/// The reason is the spec's own wording, kept for logs and for matching vectors by eye.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipError {
    /// The message is dropped without penalizing its sender.
    Ignore(&'static str),
    /// The message is invalid, and its sender is penalized.
    Reject(&'static str),
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ignore(reason) => write!(f, "ignore: {reason}"),
            Self::Reject(reason) => write!(f, "reject: {reason}"),
        }
    }
}

impl Error for GossipError {}
