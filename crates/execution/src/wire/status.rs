//! PayloadStatusV1, the engine's verdict on a payload.
//!
//! Defined in `src/engine/paris.md`.
//!
//! ```text
//!     {"status":"VALID","latestValidHash":"0x..","validationError":null}
//!     {"status":"INVALID","latestValidHash":"0x..","validationError":"bad state root"}
//!     {"status":"SYNCING","latestValidHash":null,"validationError":null}
//! ```

use std::fmt;

use axiom_json::Json;
use axiom_types::Hash32;

use super::{Fields, JsonCodec, object};
use crate::{WireError, WireErrorKind};

/// The five verdicts the engine API defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PayloadStatusKind {
    /// The payload and its ancestors executed correctly.
    Valid,

    /// The payload or an ancestor failed execution.
    Invalid,

    /// The engine lacks ancestors and is fetching them.
    Syncing,

    /// The payload passed basic checks, but its parent is unknown, so it was not executed.
    Accepted,

    /// The block hash does not match the payload's contents.
    InvalidBlockHash,
}

impl PayloadStatusKind {
    /// The status as the engine writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Syncing => "SYNCING",
            Self::Accepted => "ACCEPTED",
            Self::InvalidBlockHash => "INVALID_BLOCK_HASH",
        }
    }
}

impl fmt::Display for PayloadStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl JsonCodec for PayloadStatusKind {
    fn to_json(&self) -> Json {
        Json::from(self.as_str())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        // Exact, case-sensitive names; anything else is an unknown verdict.
        match value.as_str() {
            Some("VALID") => Ok(Self::Valid),
            Some("INVALID") => Ok(Self::Invalid),
            Some("SYNCING") => Ok(Self::Syncing),
            Some("ACCEPTED") => Ok(Self::Accepted),
            Some("INVALID_BLOCK_HASH") => Ok(Self::InvalidBlockHash),
            Some(other) => Err(WireError::new(WireErrorKind::UnknownStatus(
                other.to_owned(),
            ))),
            None => Err(WireError::wrong_type("string", value)),
        }
    }
}

/// The engine's verdict on a payload, with the hash it last found valid.
///
/// The spec ties the hash to the verdict, yet engines differ at the edges.
/// The hash is kept as sent rather than forced to match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadStatus {
    /// The verdict.
    pub status: PayloadStatusKind,

    /// The most recent valid block in the payload's chain, when the engine knows it.
    ///
    /// A valid verdict carries the payload's own hash.
    /// An invalid verdict carries the last valid ancestor, or nothing when unknown.
    pub latest_valid_hash: Option<Hash32>,

    /// The engine's explanation of an invalid verdict.
    pub validation_error: Option<String>,
}

impl PayloadStatus {
    /// The verdict as the state transition consumes it.
    ///
    /// # Returns
    ///
    /// - Valid: true.
    /// - Invalid and invalid block hash: false.
    /// - Syncing and accepted: nothing, since the engine has not judged the payload.
    ///   The block may then be imported optimistically, per the sync/optimistic spec.
    #[must_use]
    pub const fn verdict(&self) -> Option<bool> {
        match self.status {
            PayloadStatusKind::Valid => Some(true),
            PayloadStatusKind::Invalid | PayloadStatusKind::InvalidBlockHash => Some(false),
            PayloadStatusKind::Syncing | PayloadStatusKind::Accepted => None,
        }
    }
}

impl JsonCodec for PayloadStatus {
    fn to_json(&self) -> Json {
        object([
            ("status", self.status.to_json()),
            ("latestValidHash", self.latest_valid_hash.to_json()),
            ("validationError", self.validation_error.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            status: fields.required("status")?,
            latest_valid_hash: fields.optional("latestValidHash")?,
            validation_error: fields.optional("validationError")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn status_round_trip(
            kind in 0_usize..5,
            hash in proptest::option::of(any::<[u8; 32]>()),
            message in proptest::option::of(".{0,20}"),
        ) {
            let status = PayloadStatus {
                status: [
                    PayloadStatusKind::Valid,
                    PayloadStatusKind::Invalid,
                    PayloadStatusKind::Syncing,
                    PayloadStatusKind::Accepted,
                    PayloadStatusKind::InvalidBlockHash,
                ][kind],
                latest_valid_hash: hash.map(Hash32),
                validation_error: message,
            };
            prop_assert_eq!(PayloadStatus::from_json(&status.to_json()), Ok(status));
        }
    }
}
