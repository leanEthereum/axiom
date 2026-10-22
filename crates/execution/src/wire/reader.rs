//! Typed reads of JSON values, with errors that name the rule broken.
//!
//! ```text
//!     value     text, QUANTITY, DATA, or array    a single value
//!     items     the elements of an array           decoded one by one, located by index
//!     fields    the members of an object           decoded by name, located by member
//! ```

use axiom_json::{Data, Json, Object, Quantity};

use super::JsonCodec;
use crate::{WireError, WireErrorKind};

/// Typed access to one JSON value of the engine API.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a>(&'a Json);

impl<'a> Reader<'a> {
    /// Views a value.
    pub(crate) const fn new(value: &'a Json) -> Self {
        Self(value)
    }

    /// The text of a value that must be a string.
    pub(crate) fn text(self) -> Result<&'a str, WireError> {
        self.0
            .as_str()
            .ok_or_else(|| WireError::wrong_type("string", self.0))
    }

    /// Reads a QUANTITY of up to 64 bits.
    pub(crate) fn quantity(self) -> Result<u64, WireError> {
        u64::from_quantity(self.text()?).map_err(WireError::hex)
    }

    /// Reads a DATA of exactly N bytes.
    pub(crate) fn data<const N: usize>(self) -> Result<[u8; N], WireError> {
        <[u8; N]>::from_data(self.text()?).map_err(WireError::hex)
    }

    /// Reads a DATA of any length.
    pub(crate) fn bytes(self) -> Result<Vec<u8>, WireError> {
        Vec::<u8>::from_data(self.text()?).map_err(WireError::hex)
    }

    /// The elements of a value that must be an array.
    pub(crate) fn items(self) -> Result<Items<'a>, WireError> {
        self.0
            .as_array()
            .map(Items)
            .ok_or_else(|| WireError::wrong_type("array", self.0))
    }
}

/// The elements of a JSON array, not yet decoded.
///
/// A caller checks the count first, so an oversized array costs no element decoding.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Items<'a>(&'a [Json]);

impl<'a> Items<'a> {
    /// Views the elements of an array.
    pub(crate) const fn new(items: &'a [Json]) -> Self {
        Self(items)
    }

    /// The number of elements.
    pub(crate) const fn len(self) -> usize {
        self.0.len()
    }

    /// Decodes every element, locating any error by its index.
    pub(crate) fn decode<T: JsonCodec>(self) -> Result<Vec<T>, WireError> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, item)| T::from_json(item).map_err(|error| error.at_index(index)))
            .collect()
    }
}

/// Typed access to the members of a JSON object.
#[derive(Clone, Debug)]
pub(crate) struct Fields<'a>(&'a Object);

impl<'a> Fields<'a> {
    /// Views a value that must be an object.
    pub(crate) fn of(value: &'a Json) -> Result<Self, WireError> {
        value
            .as_object()
            .map(Self)
            .ok_or_else(|| WireError::wrong_type("object", value))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_locate_the_bad_element() {
        // Three QUANTITY strings; the third lacks its prefix.
        let array = Json::Array(vec![Json::from("0x1"), Json::from("0x2"), Json::from("3")]);
        let items = Reader::new(&array).items().expect("an array");
        assert_eq!(items.len(), 3);

        // The error names index 2, the third element.
        let error = items.decode::<u64>().unwrap_err();
        assert_eq!(error.path(), "[2]");
    }

    #[test]
    fn wrong_types_name_what_was_expected() {
        // A number where text belongs.
        let number = Json::from(7_u64);
        assert_eq!(
            Reader::new(&number).text(),
            Err(WireError::new(WireErrorKind::Type {
                expected: "string",
                found: "number"
            }))
        );

        // A string where an array belongs.
        let text = Json::from("0x1");
        assert_eq!(
            Reader::new(&text).items().map(Items::len),
            Err(WireError::new(WireErrorKind::Type {
                expected: "array",
                found: "string"
            }))
        );
    }
}
