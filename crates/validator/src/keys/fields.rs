//! Typed reads of the members of one JSON object, for keystores and deposit data.

use axiom_json::{Json, Object};

use crate::keys::{FieldError, HexError, hex::BareHex};

/// The members of one JSON object, read by name.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fields<'a> {
    /// The object.
    object: &'a Object,
    /// Its dotted path from the document root, for error messages.
    path: &'static str,
}

impl<'a> Fields<'a> {
    /// The object a value must be.
    pub(crate) fn of(json: &'a Json, path: &'static str) -> Result<Self, FieldError> {
        let object = json
            .as_object()
            .ok_or(FieldError::NotObject { object: path })?;
        Ok(Self { object, path })
    }

    /// The object a member must be, under its own dotted path.
    pub(crate) fn object(
        self,
        field: &'static str,
        path: &'static str,
    ) -> Result<Self, FieldError> {
        Fields::of(self.get(field)?, path)
    }

    /// A member that must be present.
    pub(crate) fn get(self, field: &'static str) -> Result<&'a Json, FieldError> {
        self.object.get(field).ok_or(FieldError::Missing {
            object: self.path,
            field,
        })
    }

    /// Whether a member is present.
    pub(crate) fn has(self, field: &'static str) -> bool {
        self.object.get(field).is_some()
    }

    /// A string member.
    pub(crate) fn text(self, field: &'static str) -> Result<&'a str, FieldError> {
        self.get(field)?
            .as_str()
            .ok_or_else(|| self.wrong(field, "a string"))
    }

    /// An unsigned integer member, written as a JSON number.
    pub(crate) fn number(self, field: &'static str) -> Result<u64, FieldError> {
        self.get(field)?
            .as_u64()
            .ok_or_else(|| self.wrong(field, "an unsigned 64-bit integer"))
    }

    /// An unsigned 32-bit integer member, written as a JSON number.
    pub(crate) fn number_u32(self, field: &'static str) -> Result<u32, FieldError> {
        u32::try_from(self.number(field)?).map_err(|_| self.wrong(field, "below 2^32"))
    }

    /// A hex member of any even length.
    pub(crate) fn hex(self, field: &'static str) -> Result<Vec<u8>, FieldError> {
        BareHex::decode(self.text(field)?).map_err(|source| self.bad_hex(field, source))
    }

    /// A hex member of a fixed length.
    pub(crate) fn hex_array<const N: usize>(
        self,
        field: &'static str,
    ) -> Result<[u8; N], FieldError> {
        BareHex::decode_array(self.text(field)?).map_err(|source| self.bad_hex(field, source))
    }

    /// The error for a member of the wrong type or range.
    const fn wrong(self, field: &'static str, expected: &'static str) -> FieldError {
        FieldError::Type {
            object: self.path,
            field,
            expected,
        }
    }

    /// The error for a hex member that does not decode.
    const fn bad_hex(self, field: &'static str, source: HexError) -> FieldError {
        FieldError::Hex {
            object: self.path,
            field,
            source,
        }
    }
}
