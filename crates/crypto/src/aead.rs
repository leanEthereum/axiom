//! The failure shared by every authenticated cipher in the crate.

use std::{error::Error, fmt};

/// A sealed message that fails authentication.
///
/// The error carries no detail on purpose.
/// A wrong key, a wrong nonce, altered data and a short input all look the same to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authentication failed")
    }
}

impl Error for AeadError {}
