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
mod reader;
mod requests;
mod status;
mod syncing;

use axiom_json::Json;
pub use blobs::{BlobAndProof, Blobs, BlobsBundle, CellProofs};
pub use forkchoice::{ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId};
pub use get_payload::GetPayloadResponse;
pub(crate) use reader::{Fields, Items, Reader};
pub use requests::RequestsList;
pub use status::{PayloadStatus, PayloadStatusKind};
pub use syncing::SyncStatus;

use crate::WireError;

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
