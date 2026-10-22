//! The JSON mapping of SSZ values, as the beacon node API and the spec's vectors write them.
//!
//! # Overview
//!
//! Every SSZ type maps to JSON by its kind alone:
//!
//! ```text
//!     boolean                       true
//!     uintN                         "12345"                 decimal, in a string
//!     ByteVector, ByteList          "0x0a1b"                hex
//!     Bitvector, Bitlist            "0x05"                  hex of the SSZ encoding
//!     Vector, List                  [ ... ]
//!     Container                     {"name": ...}           fields in declaration order
//!     CompatibleUnion               {"selector": "1", "data": ...}
//! ```
//!
//! A type's schema says which kind it is, so one codec serves every type.
//!
//! Encoding walks the value's SSZ bytes along its schema.
//! Decoding writes SSZ bytes from the JSON along the schema, then decodes them as SSZ.
//! The SSZ decoder thus checks every limit and invariant a JSON value must satisfy too.
//!
//! See the beacon API's type definitions, and the YAML values of the spec's SSZ vectors.

mod decoder;
mod encoder;
mod error;
mod uint;

use axiom_ssz::Ssz;
pub(crate) use decoder::JsonDecoder;
pub(crate) use encoder::JsonEncoder;
pub use error::SszJsonError;

use crate::Json;

/// A value with a JSON form fixed by its SSZ schema.
///
/// Every SSZ type has one.
pub trait SszJson: Ssz {
    /// The value's JSON form.
    #[must_use]
    fn to_json(&self) -> Json;

    /// Reads a value from its JSON form.
    ///
    /// Integers may be decimal strings or JSON numbers; output always uses strings.
    /// Hex digits may be either case.
    ///
    /// # Errors
    ///
    /// Fails when the JSON does not follow the schema, naming where it strays.
    /// Fails when the value breaks a limit or invariant of its SSZ type.
    fn from_json(json: &Json) -> Result<Self, SszJsonError>;
}

impl<T: Ssz> SszJson for T {
    fn to_json(&self) -> Json {
        // Invariant: a value's encoding follows its type's schema.
        // Every container lists its fields once, by name and type, and its layout derives from that list.
        // Debug builds check each visited field against the list; the spec's vectors pin the rest.
        // So walking the encoding along the schema never meets malformed bytes.
        let json = JsonEncoder::new(&self.encode()).value(&T::SCHEMA);
        debug_assert!(json.is_ok(), "an encoding strays from its schema: {json:?}");
        json.unwrap_or(Json::Null)
    }

    fn from_json(json: &Json) -> Result<Self, SszJsonError> {
        let bytes = JsonDecoder::new().value(&T::SCHEMA, json)?;
        Ok(T::decode(&bytes)?)
    }
}

#[cfg(test)]
mod tests;
