//! Header fields.

use std::slice;

/// Header fields in arrival order, names stored in lowercase.
///
/// Field names are case-insensitive per RFC 9110 section 5.1.
/// Lowercasing once on entry makes every lookup a plain comparison.
/// A name may repeat, as RFC 9110 section 5.3 allows for list-valued fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    /// Lowercase name and value pairs.
    entries: Vec<(String, String)>,
}

impl Headers {
    /// No fields.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of fields, counting repeats.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no fields.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first value of a field, by case-insensitive name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(stored, _)| stored.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value of a field, in arrival order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        // Stored names are lowercase, so compare against the query ignoring ASCII case.
        self.entries
            .iter()
            .filter(move |(stored, _)| stored.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether a comma-separated field lists a token, ignoring case.
    ///
    /// ```text
    ///     connection: keep-alive, Close    contains "close" -> true
    /// ```
    #[must_use]
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        // Split every value of the field on commas and trim the optional whitespace.
        self.get_all(name)
            .flat_map(|value| value.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    }

    /// Adds a field after any existing ones of the same name.
    ///
    /// The serializer rejects names and values that are not valid on the wire.
    pub fn append(&mut self, name: &str, value: impl Into<String>) {
        self.entries.push((name.to_ascii_lowercase(), value.into()));
    }

    /// Sets a field, replacing every existing value of that name.
    pub fn insert(&mut self, name: &str, value: impl Into<String>) {
        self.remove(name);
        self.append(name, value);
    }

    /// Removes every value of a field.
    pub fn remove(&mut self, name: &str) {
        self.entries
            .retain(|(stored, _)| !stored.eq_ignore_ascii_case(name));
    }

    /// The fields, in order, as lowercase name and value pairs.
    pub fn iter(&self) -> slice::Iter<'_, (String, String)> {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a (String, String);
    type IntoIter = slice::Iter<'a, (String, String)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// Whether a byte may appear in a token, such as a field name or a method.
///
/// RFC 9110 section 5.6.2: any visible ASCII except the delimiters.
pub(crate) const fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`'
            | b'|' | b'~'
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

/// Whether a byte may appear in a field value.
///
/// RFC 9110 section 5.5: visible ASCII, space, tab, and bytes from 0x80 up.
/// Carriage return, line feed, and NUL are excluded, which blocks header injection.
pub(crate) const fn is_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_case_insensitive() {
        // Two fields appended under different casings land under one lowercase name.
        let mut headers = Headers::new();
        headers.append("Content-Type", "application/json");
        headers.append("X-Multi", "a");
        headers.append("x-multi", "b");

        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert_eq!(headers.get_all("X-MULTI").collect::<Vec<_>>(), ["a", "b"]);

        // Insert replaces both values of the repeated field with one.
        headers.insert("x-Multi", "c");
        assert_eq!(headers.get_all("x-multi").collect::<Vec<_>>(), ["c"]);
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn token_lists_are_split_and_trimmed() {
        // "close" appears second in the list, with odd casing and spacing.
        let mut headers = Headers::new();
        headers.append("connection", "keep-alive ,  Close");
        assert!(headers.has_token("Connection", "close"));
        assert!(!headers.has_token("connection", "upgrade"));
    }
}
