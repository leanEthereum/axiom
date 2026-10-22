//! The JSON form of consensus containers, as the beacon node and builder APIs carry them.
//!
//! # Overview
//!
//! The beacon node API and the builder API exchange consensus containers as JSON.
//! Their encoding rules come from `types/primitive.yaml` of `ethereum/beacon-APIs`.
//!
//! ```text
//!     unsigned integers, every width    decimal string       "0", "1024"
//!     booleans                          JSON boolean         true
//!     byte vectors and byte lists       0x-prefixed hex      "0x0041"
//!     bitlists and bitvectors           hex of the SSZ bytes "0x05"
//!     lists and vectors                 array                element by element
//!     containers                        object               snake_case spec field names
//! ```
//!
//! Decoding is strict about types, lengths, and bounds.
//! A decimal must be canonical: digits only, no sign, no leading zero, within the type's range.
//! A list over its limit is refused before any element is decoded.
//!
//! The API's own messages around the containers, such as duties, live in the api module.
//!
//! Decoding ignores unknown members, so a server that adds a field still interoperates.
//!
//! A container whose shape varies by fork travels without its fork.
//! The API names it in a header or a sibling member instead.
//! Those containers implement a second trait whose decoder takes the fork.
//! No type implements both traits, so the shared encoder name never clashes at a call site.

mod altair;
pub mod api;
mod bellatrix;
mod capella;
mod collections;
mod combined;
mod decimal;
mod deneb;
mod electra;
mod error;
mod fulu;
mod gloas;
mod phase0;
mod primitives;
mod reader;
#[cfg(test)]
mod sample;

use axiom_json::Json;
use axiom_types::ForkName;
pub use decimal::DecimalError;
pub use error::{ApiJsonError, ApiJsonErrorKind};
pub use reader::Fields;

/// A value with one JSON form in the beacon node and builder APIs.
pub trait ApiJson: Sized {
    /// The JSON form.
    fn to_json(&self) -> Json;

    /// Reads the JSON form.
    ///
    /// # Errors
    ///
    /// Fails when the value has the wrong type, encoding, length, or range, naming where.
    fn from_json(value: &Json) -> Result<Self, ApiJsonError>;
}

/// A value of any fork whose JSON form does not record its fork.
///
/// The fork comes from outside the value, such as a version header.
pub trait ForkedJson: Sized {
    /// The JSON form of the fork's container.
    fn to_json(&self) -> Json;

    /// Reads the JSON form of a container of the given fork.
    ///
    /// # Errors
    ///
    /// Fails when the fork has no such container, or the value is not one of that fork.
    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError>;
}
