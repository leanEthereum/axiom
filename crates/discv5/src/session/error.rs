//! Reasons a sealed message does not open.

use std::{error::Error, fmt};

use crate::message::MessageError;

/// A packet whose message fails to authenticate or decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The tag does not verify under the session's read key.
    Authentication,

    /// The plaintext is not a valid message.
    Message(MessageError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication => f.write_str("message fails authentication"),
            Self::Message(error) => write!(f, "decrypted message: {error}"),
        }
    }
}

impl Error for OpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authentication => None,
            Self::Message(error) => Some(error),
        }
    }
}
