//! The beacon API's JSON form of consensus containers, both ways.
//!
//! # Overview
//!
//! The beacon API, the remote signing API, and the keymanager API share one JSON convention.
//!
//! - Integers are decimal strings, so 64-bit values survive JavaScript readers.
//! - Byte strings are 0x-prefixed lowercase hex.
//! - Bitfields are the hex of their SSZ bytes, delimiter bit included for lists.
//! - Containers are objects whose members carry the spec's field names.
//!
//! See the `ethereum/beacon-APIs` repository, types directory.
//!
//! Every decoded value is attacker-controlled, so each length and bound is checked here.

mod altair;
mod bellatrix;
mod capella;
mod electra;
mod error;
mod gloas;
mod phase0;
mod primitives;
mod reader;

use axiom_json::Json;
pub use error::JsonError;
pub use reader::Fields;

/// A value with a JSON form in the beacon API.
pub trait ApiJson: Sized {
    /// The value as JSON.
    fn to_json(&self) -> Json;

    /// The value read from JSON.
    ///
    /// # Errors
    ///
    /// Fails when the JSON has the wrong shape, or a value is out of range.
    fn from_json(json: &Json) -> Result<Self, JsonError>;
}
