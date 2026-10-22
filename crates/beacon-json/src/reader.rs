//! Typed reads of JSON values, with errors that name the rule broken.
//!
//! ```text
//!     value     text, decimal, hex, or array    a single value
//!     items     the elements of an array        decoded one by one, located by index
//!     fields    the members of an object        decoded by name, located by member
//! ```

use axiom_json::{Data, Json, Object};
use axiom_ssz::U256;

use crate::{ApiJson, ApiJsonError, ApiJsonErrorKind, decimal::Decimal};

/// Typed access to one JSON value of the beacon API.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a>(&'a Json);

impl<'a> Reader<'a> {
    /// Views a value.
    pub(crate) const fn new(value: &'a Json) -> Self {
        Self(value)
    }

    /// The text of a value that must be a string, naming what the string should hold.
    fn text(self, expected: &'static str) -> Result<&'a str, ApiJsonError> {
        self.0
            .as_str()
            .ok_or_else(|| ApiJsonError::wrong_type(expected, self.0))
    }

    /// The digits of a canonical decimal string.
    fn decimal(self) -> Result<Decimal<'a>, ApiJsonError> {
        Decimal::parse(self.text("a decimal string")?).map_err(ApiJsonError::decimal)
    }

    /// Reads a canonical decimal string of a 64-bit value.
    pub(crate) fn u64(self) -> Result<u64, ApiJsonError> {
        self.decimal()?.to_u64().map_err(ApiJsonError::decimal)
    }

    /// Reads a canonical decimal string of a 256-bit value.
    pub(crate) fn u256(self) -> Result<U256, ApiJsonError> {
        self.decimal()?.to_u256().map_err(ApiJsonError::decimal)
    }

    /// Reads hex of exactly N bytes.
    pub(crate) fn hex_array<const N: usize>(self) -> Result<[u8; N], ApiJsonError> {
        <[u8; N]>::from_data(self.text("a hex string")?).map_err(ApiJsonError::hex)
    }

    /// Reads hex of any length, after a check on the byte count made before any digit is decoded.
    ///
    /// The early check keeps a 128 KiB blob of the wrong size from being decoded at all.
    pub(crate) fn hex_bytes(
        self,
        check: impl FnOnce(usize) -> Result<(), ApiJsonErrorKind>,
    ) -> Result<Vec<u8>, ApiJsonError> {
        let text = self.text("a hex string")?;
        // Only a well-formed prefix and an even digit count give a byte count to check.
        // Anything else fails the decoding below with the precise hex error.
        if let Some(digits) = text.strip_prefix("0x")
            && digits.len().is_multiple_of(2)
        {
            check(digits.len() / 2)?;
        }
        Vec::<u8>::from_data(text).map_err(ApiJsonError::hex)
    }

    /// The elements of a value that must be an array.
    pub(crate) fn items(self) -> Result<Items<'a>, ApiJsonError> {
        self.0
            .as_array()
            .map(Items)
            .ok_or_else(|| ApiJsonError::wrong_type("an array", self.0))
    }
}

/// The elements of a JSON array, not yet decoded.
///
/// A caller checks the count first, so an oversized array costs no element decoding.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Items<'a>(&'a [Json]);

impl Items<'_> {
    /// The number of elements.
    pub(crate) const fn len(self) -> usize {
        self.0.len()
    }

    /// Decodes every element, locating any error by its index.
    pub(crate) fn decode<T: ApiJson>(self) -> Result<Vec<T>, ApiJsonError> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, item)| T::from_json(item).map_err(|error| error.at_index(index)))
            .collect()
    }
}

/// Typed access to the members of a JSON object.
///
/// The API's own envelopes, such as a data member beside a version, are read with it too.
#[derive(Clone, Copy, Debug)]
pub struct Fields<'a>(&'a Object);

impl<'a> Fields<'a> {
    /// Views a value that must be an object.
    ///
    /// # Errors
    ///
    /// Fails when the value is not an object.
    pub fn of(value: &'a Json) -> Result<Self, ApiJsonError> {
        value
            .as_object()
            .map(Self)
            .ok_or_else(|| ApiJsonError::wrong_type("an object", value))
    }

    /// Reads a member that must be present and not null.
    ///
    /// Members the container does not name are never read, so they are ignored.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent, null, or malformed, naming it.
    pub fn required<T: ApiJson>(self, name: &'static str) -> Result<T, ApiJsonError> {
        match self.0.get(name) {
            None | Some(Json::Null) => {
                Err(ApiJsonError::new(ApiJsonErrorKind::Missing).in_member(name))
            }
            Some(value) => T::from_json(value).map_err(|error| error.in_member(name)),
        }
    }

    /// Reads a member that may be absent or null.
    ///
    /// # Errors
    ///
    /// Fails when the member is present and malformed, naming it.
    pub fn optional<T: ApiJson>(self, name: &'static str) -> Result<Option<T>, ApiJsonError> {
        match self.0.get(name) {
            None | Some(Json::Null) => Ok(None),
            Some(value) => T::from_json(value)
                .map(Some)
                .map_err(|error| error.in_member(name)),
        }
    }

    /// The JSON value of a member that must be present and not null.
    ///
    /// # Errors
    ///
    /// Fails when the member is absent or null, naming it.
    pub fn raw(self, name: &'static str) -> Result<&'a Json, ApiJsonError> {
        match self.0.get(name) {
            None | Some(Json::Null) => {
                Err(ApiJsonError::new(ApiJsonErrorKind::Missing).in_member(name))
            }
            Some(value) => Ok(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_json::HexError;

    use super::*;
    use crate::DecimalError;

    #[test]
    fn items_locate_the_bad_element() {
        // Three decimals; the third has a sign.
        let array = Json::Array(vec![Json::from("1"), Json::from("2"), Json::from("+3")]);
        let items = Reader::new(&array).items().unwrap();
        assert_eq!(items.len(), 3);

        // The error names index 2, the third element, and the sign at byte 0.
        assert_eq!(
            items.decode::<u64>(),
            Err(
                ApiJsonError::new(ApiJsonErrorKind::Decimal(DecimalError::InvalidDigit {
                    offset: 0
                }))
                .at_index(2)
            )
        );
    }

    #[test]
    fn fields_locate_the_bad_member_and_ignore_unknown_ones() {
        // An object with a valid member, an unknown one, and a null one.
        let object = Json::from([
            ("epoch", Json::from("5")),
            ("future_field", Json::from(true)),
            ("root", Json::Null),
        ]);
        let fields = Fields::of(&object).unwrap();

        // The valid member reads, and the unknown one never matters.
        assert_eq!(fields.required::<u64>("epoch"), Ok(5));

        // Null and absent members are both missing, located by name.
        let missing = |name| Err(ApiJsonError::new(ApiJsonErrorKind::Missing).in_member(name));
        assert_eq!(fields.required::<u64>("root"), missing("root"));
        assert_eq!(fields.required::<u64>("slot"), missing("slot"));
    }

    #[test]
    fn wrong_types_name_what_was_expected() {
        // A number where a decimal string belongs.
        let number = Json::from(7_u64);
        assert_eq!(
            Reader::new(&number).u64(),
            Err(ApiJsonError::new(ApiJsonErrorKind::Type {
                expected: "a decimal string",
                found: "number"
            }))
        );

        // A string where an array belongs.
        let text = Json::from("1");
        assert_eq!(
            Reader::new(&text).items().map(Items::len),
            Err(ApiJsonError::new(ApiJsonErrorKind::Type {
                expected: "an array",
                found: "string"
            }))
        );

        // An array where an object belongs.
        let array = Json::Array(Vec::new());
        assert_eq!(
            Fields::of(&array).map(|_| ()),
            Err(ApiJsonError::new(ApiJsonErrorKind::Type {
                expected: "an object",
                found: "array"
            }))
        );
    }

    #[test]
    fn hex_bytes_check_the_count_before_decoding() {
        // Three bytes against a check that admits at most two.
        let at_most_two = |actual| {
            if actual > 2 {
                Err(ApiJsonErrorKind::TooLong { limit: 2, actual })
            } else {
                Ok(())
            }
        };
        let three = Json::from("0x010203");
        assert_eq!(
            Reader::new(&three).hex_bytes(at_most_two),
            Err(ApiJsonError::new(ApiJsonErrorKind::TooLong {
                limit: 2,
                actual: 3
            }))
        );

        // Odd digits skip the check and fail as hex.
        let odd = Json::from("0x010");
        assert_eq!(
            Reader::new(&odd).hex_bytes(at_most_two),
            Err(ApiJsonError::new(ApiJsonErrorKind::Hex(
                HexError::OddLength { digits: 3 }
            )))
        );
    }
}
