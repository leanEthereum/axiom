//! Reasons a sealed message does not open.

use thiserror::Error;

use crate::message::MessageError;

/// A packet whose message fails to authenticate or decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum OpenError {
    /// The tag does not verify under the session's read key.
    #[error("message fails authentication")]
    Authentication,

    /// The plaintext is not a valid message.
    #[error("decrypted message: {0}")]
    Message(#[source] MessageError),
}
