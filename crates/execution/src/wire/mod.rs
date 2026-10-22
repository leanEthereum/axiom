//! The JSON form of engine API structures.
//!
//! Every structure maps member by member onto a consensus container.
//! Integers travel as QUANTITY and byte strings as DATA, per `src/engine/common.md`.
//!
//! ```text
//!     consensus field      JSON member         encoding
//!     block_number: u64    "blockNumber"       QUANTITY   "0x1b4"
//!     block_hash: Hash32   "blockHash"         DATA       "0x" + 64 hex digits
//!     withdrawals: List    "withdrawals"       array of objects
//! ```
//!
//! Decoding is strict about types and lengths and lenient about extra members.
//! An unknown member is ignored, so a newer engine that adds fields still interoperates.

mod blobs;
mod forkchoice;
mod get_payload;
mod payload;
mod primitives;
pub mod requests;
mod status;
mod syncing;

use axiom_json::{Json, Object};
pub use blobs::{BlobAndProof, Blobs, BlobsBundle, CellProofs};
pub use forkchoice::{ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId};
pub use get_payload::GetPayloadResponse;
pub use status::{PayloadStatus, PayloadStatusKind};
pub use syncing::SyncStatus;

use crate::{WireError, WireErrorKind};

/// A value with a JSON form in the engine API.
///
/// Implemented for the consensus containers the engine exchanges and their fields.
pub trait JsonCodec: Sized {
    /// The JSON form.
    fn to_json(&self) -> Json;

    /// Reads the JSON form.
    ///
    /// # Errors
    ///
    /// Fails when the value has the wrong type, encoding, or length, naming where.
    fn from_json(value: &Json) -> Result<Self, WireError>;
}

/// Builds an object from members in order.
pub(crate) fn object<const N: usize>(members: [(&str, Json); N]) -> Json {
    let mut object = Object::new();
    for (name, value) in members {
        object.insert(name, value);
    }
    Json::Object(object)
}

/// The error for a value of the wrong JSON type.
pub(crate) const fn wrong_type(expected: &'static str, found: &Json) -> WireError {
    WireError::new(WireErrorKind::Type {
        expected,
        found: found.kind(),
    })
}

/// Typed access to the members of a JSON object.
pub(crate) struct Fields<'a>(&'a Object);

impl<'a> Fields<'a> {
    /// Views a value that must be an object.
    pub(crate) fn of(value: &'a Json) -> Result<Self, WireError> {
        value
            .as_object()
            .map(Self)
            .ok_or_else(|| wrong_type("object", value))
    }

    /// Reads a member that must be present and not null.
    pub(crate) fn required<T: JsonCodec>(&self, name: &'static str) -> Result<T, WireError> {
        match self.0.get(name) {
            // The spec treats a null member as not provided.
            None | Some(Json::Null) => Err(WireError::new(WireErrorKind::Missing).in_member(name)),
            Some(value) => T::from_json(value).map_err(|error| error.in_member(name)),
        }
    }

    /// Reads a member that may be absent or null.
    pub(crate) fn optional<T: JsonCodec>(
        &self,
        name: &'static str,
    ) -> Result<Option<T>, WireError> {
        match self.0.get(name) {
            None | Some(Json::Null) => Ok(None),
            Some(value) => T::from_json(value)
                .map(Some)
                .map_err(|error| error.in_member(name)),
        }
    }
}

/// The JSON form of an optional value: the value, or null.
pub(crate) fn nullable<T: JsonCodec>(value: Option<&T>) -> Json {
    value.map_or(Json::Null, JsonCodec::to_json)
}
