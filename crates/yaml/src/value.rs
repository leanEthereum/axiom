//! A parsed YAML node and its typed views.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use crate::{Mapping, ParseError, emitter::Emitter, parser::Parser};

/// One node of a YAML document.
///
/// Plain scalars resolve per the YAML 1.2 core schema for nulls and booleans only.
/// Every other scalar, numbers included, stays text.
/// The typed views read numbers and hex bytes out of that text on demand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Yaml {
    /// An empty value, or a plain `null`, `Null`, `NULL`, or `~`.
    #[default]
    Null,

    /// A plain `true` or `false`, in lower, title, or upper case.
    Bool(bool),

    /// Any other scalar, as written once quotes and escapes are decoded.
    String(String),

    /// An ordered list of nodes.
    Sequence(Vec<Self>),

    /// Keys and values in document order.
    Mapping(Mapping),
}

impl Yaml {
    /// Parses a text holding exactly one document.
    ///
    /// # Errors
    ///
    /// Fails on malformed YAML and on valid YAML outside the supported subset.
    /// The error carries the line and column of the first problem.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        Parser::new(text).document()
    }

    /// Resolves a plain scalar per the YAML 1.2 core schema.
    ///
    /// Quoted scalars never resolve, so `'true'` stays text.
    pub(crate) fn from_plain(text: String) -> Self {
        match text.as_str() {
            "null" | "Null" | "NULL" | "~" => Self::Null,
            "true" | "True" | "TRUE" => Self::Bool(true),
            "false" | "False" | "FALSE" => Self::Bool(false),
            _ => Self::String(text),
        }
    }

    /// The value under a key, when this node is a mapping holding it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_mapping()?.get(key)
    }

    /// Whether the node is null.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The boolean, when the node is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The text, when the node is a string scalar.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// The scalar read as an unsigned decimal integer.
    ///
    /// Only ASCII digits are accepted: no sign, no underscores, no hex.
    /// Leading zeros are allowed, as in the core schema.
    /// Values of 2^64 or more give none rather than wrap.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        let text = self.as_str()?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Digits only, so the standard parser fails solely on overflow.
        text.parse().ok()
    }

    /// The scalar read as `0x`-prefixed hex, decoded into bytes.
    ///
    /// Digits may be upper or lower case.
    /// An odd number of digits gives none, since bytes come in digit pairs.
    #[must_use]
    pub fn as_hex_bytes(&self) -> Option<Vec<u8>> {
        let digits = self.as_str()?.strip_prefix("0x")?.as_bytes();
        let (pairs, odd) = digits.as_chunks::<2>();
        if !odd.is_empty() {
            return None;
        }
        // The standard digit parse takes either case, and two digits always fit a byte.
        let nibble = |byte: u8| char::from(byte).to_digit(16);
        pairs
            .iter()
            .map(|&[high, low]| u8::try_from((nibble(high)? << 4) | nibble(low)?).ok())
            .collect()
    }

    /// The scalar read as `0x`-prefixed hex of exactly `N` bytes.
    ///
    /// Fits roots, public keys, and every other fixed-size byte field of the vectors.
    #[must_use]
    pub fn as_hex_array<const N: usize>(&self) -> Option<[u8; N]> {
        self.as_hex_bytes()?.try_into().ok()
    }

    /// The items, when the node is a sequence.
    #[must_use]
    pub fn as_sequence(&self) -> Option<&[Self]> {
        match self {
            Self::Sequence(items) => Some(items),
            _ => None,
        }
    }

    /// The entries, when the node is a mapping.
    #[must_use]
    pub const fn as_mapping(&self) -> Option<&Mapping> {
        match self {
            Self::Mapping(mapping) => Some(mapping),
            _ => None,
        }
    }
}

impl FromStr for Yaml {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, ParseError> {
        Self::parse(text)
    }
}

impl Display for Yaml {
    /// Writes the node as a block-style document ending in a newline.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Emitter::new(f).document(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(text: &str) -> Yaml {
        Yaml::String(text.into())
    }

    #[test]
    fn core_schema_resolves_null_and_bool_spellings() {
        // Every spelling the core schema lists, and nothing else.
        for text in ["null", "Null", "NULL", "~"] {
            assert_eq!(Yaml::from_plain(text.into()), Yaml::Null);
        }
        for text in ["true", "True", "TRUE"] {
            assert_eq!(Yaml::from_plain(text.into()), Yaml::Bool(true));
        }
        for text in ["false", "False", "FALSE"] {
            assert_eq!(Yaml::from_plain(text.into()), Yaml::Bool(false));
        }

        // YAML 1.1 spellings are plain text under 1.2.
        for text in ["yes", "no", "on", "off", "nULL", "tRUE"] {
            assert_eq!(Yaml::from_plain(text.into()), string(text));
        }
    }

    #[test]
    fn u64_accepts_only_in_range_decimal_digits() {
        // Boundaries: 0 and 2^64 - 1 parse, 2^64 overflows.
        assert_eq!(string("0").as_u64(), Some(0));
        assert_eq!(string("007").as_u64(), Some(7));
        assert_eq!(string("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(string("18446744073709551616").as_u64(), None);

        // Signs, hex, separators, whitespace, and the empty string are not decimal digits.
        for text in ["", "+1", "-1", "0x10", "1_000", " 1", "1.0"] {
            assert_eq!(string(text).as_u64(), None, "{text:?}");
        }

        // Non-strings have no integer view.
        assert_eq!(Yaml::Null.as_u64(), None);
        assert_eq!(Yaml::Bool(true).as_u64(), None);
    }

    #[test]
    fn hex_bytes_decode_digit_pairs() {
        // "0x" alone is the empty byte string.
        assert_eq!(string("0x").as_hex_bytes(), Some(vec![]));
        assert_eq!(
            string("0x00ff10Ab").as_hex_bytes(),
            Some(vec![0, 0xff, 0x10, 0xab])
        );

        // Odd length, bad digit, missing or upper-case prefix.
        for text in ["0x123", "0x0g", "00ff", "0X00", ""] {
            assert_eq!(string(text).as_hex_bytes(), None, "{text:?}");
        }
    }

    #[test]
    fn hex_array_requires_the_exact_length() {
        // Two bytes fit a two-byte array, and no other size.
        let value = string("0xbeef");
        assert_eq!(value.as_hex_array::<2>(), Some([0xbe, 0xef]));
        assert_eq!(value.as_hex_array::<1>(), None);
        assert_eq!(value.as_hex_array::<3>(), None);
    }

    #[test]
    fn views_match_only_their_own_variant() {
        let mut mapping = Mapping::new();
        mapping.insert("k", Yaml::Bool(false));
        let map = Yaml::Mapping(mapping);
        let seq = Yaml::Sequence(vec![Yaml::Null]);

        // Each view answers for its variant and declines the others.
        assert_eq!(map.get("k"), Some(&Yaml::Bool(false)));
        assert_eq!(map.get("missing"), None);
        assert_eq!(seq.get("k"), None);
        assert_eq!(seq.as_sequence(), Some(&[Yaml::Null][..]));
        assert_eq!(map.as_sequence(), None);
        assert_eq!(seq.as_mapping(), None);
        assert_eq!(Yaml::Bool(true).as_bool(), Some(true));
        assert_eq!(string("true").as_bool(), None);
        assert_eq!(Yaml::Null.as_str(), None);
        assert!(Yaml::Null.is_null());
        assert!(!string("").is_null());
    }
}
