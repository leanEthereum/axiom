//! A parsed JSON value and its typed views.

use crate::{Limits, Number, Object, ParseError, parser::Parser};

/// One JSON value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Json {
    /// The literal `null`.
    #[default]
    Null,

    /// The literal `true` or `false`.
    Bool(bool),

    /// A number, kept as its text.
    Number(Number),

    /// A string, with escapes decoded.
    String(String),

    /// An ordered list of values.
    Array(Vec<Self>),

    /// Named members in document order.
    Object(Object),
}

impl Json {
    /// Parses a text holding exactly one value, under the default limits.
    ///
    /// # Errors
    ///
    /// Fails on any text outside RFC 8259 and on a repeated member name.
    /// The error carries the byte offset of the first problem.
    pub fn parse(text: impl AsRef<[u8]>) -> Result<Self, ParseError> {
        Self::parse_with(text, Limits::default())
    }

    /// Parses a text holding exactly one value, under explicit limits.
    ///
    /// # Errors
    ///
    /// Fails like the default parse, and when the text breaks a limit.
    pub fn parse_with(text: impl AsRef<[u8]>, limits: Limits) -> Result<Self, ParseError> {
        Parser::new(text.as_ref(), limits).document()
    }

    /// The value of an object member, when this value is an object holding it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Self> {
        self.as_object()?.get(name)
    }

    /// Whether the value is null.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The boolean, when the value is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The number, when the value is one.
    #[must_use]
    pub const fn as_number(&self) -> Option<&Number> {
        match self {
            Self::Number(number) => Some(number),
            _ => None,
        }
    }

    /// The unsigned integer, when the value is a number written as one.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number()?.as_u64()
    }

    /// The signed integer, when the value is a number written as one.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number()?.as_i64()
    }

    /// The text, when the value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// The items, when the value is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The members, when the value is an object.
    #[must_use]
    pub const fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    /// The kind of value, as RFC 8259 names it.
    ///
    /// Error messages use it to say what was found instead of what was expected.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for Json {
    fn from(value: u64) -> Self {
        Self::Number(Number::from(value))
    }
}

impl From<i64> for Json {
    fn from(value: i64) -> Self {
        Self::Number(Number::from(value))
    }
}

impl From<Number> for Json {
    fn from(value: Number) -> Self {
        Self::Number(value)
    }
}

impl From<String> for Json {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<Vec<Self>> for Json {
    fn from(value: Vec<Self>) -> Self {
        Self::Array(value)
    }
}

impl From<Object> for Json {
    fn from(value: Object) -> Self {
        Self::Object(value)
    }
}

impl<T: Into<Self>> From<Option<T>> for Json {
    /// Maps an absent value to null, as JSON-RPC does for optional fields.
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}
