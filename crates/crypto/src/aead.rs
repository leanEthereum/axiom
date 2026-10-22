//! The failure shared by every authenticated cipher in the crate.

use thiserror::Error;

/// A sealed message that fails authentication.
///
/// The error carries no detail on purpose.
/// A wrong key, a wrong nonce, altered data and a short input all look the same to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("authentication failed")]
pub struct AeadError;
