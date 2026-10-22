//! Header fields.

use std::slice;

use crate::{BodyLength, ProtocolError};

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

    /// The framing the fields declare, if any.
    ///
    /// Both declarations at once are refused rather than resolved.
    /// RFC 9112 section 6.3 allows that, and it shuts the door on request smuggling.
    pub(crate) fn body_framing(&self) -> Result<Option<BodyLength>, ProtocolError> {
        let length = self.content_length()?;
        let mut codings = self.get_all("transfer-encoding").peekable();

        if codings.peek().is_none() {
            // No transfer coding: the content length frames the body, if present.
            return Ok(length.map(BodyLength::Fixed));
        }
        if length.is_some() {
            return Err(ProtocolError::ConflictingLength);
        }

        // Exactly one coding, chunked, across all transfer-encoding fields.
        let mut list = codings
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|item| !item.is_empty());
        match (list.next(), list.next()) {
            (Some(coding), None) if coding.eq_ignore_ascii_case("chunked") => {
                Ok(Some(BodyLength::Chunked))
            }
            _ => Err(ProtocolError::UnsupportedTransferEncoding),
        }
    }

    /// The declared content length, when present.
    ///
    /// Repeated values are allowed only when identical, per RFC 9112 section 6.3 rule 5.
    fn content_length(&self) -> Result<Option<u64>, ProtocolError> {
        let mut length = None;
        // A field may repeat, and one field may hold a comma-separated list.
        for item in self
            .get_all("content-length")
            .flat_map(|value| value.split(','))
        {
            let item = item.trim();
            // Digits only; a sign, a space, or hex is malformed.
            if item.is_empty() || !item.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ProtocolError::InvalidContentLength);
            }
            let value: u64 = item
                .parse()
                .map_err(|_| ProtocolError::InvalidContentLength)?;
            match length {
                Some(previous) if previous != value => {
                    return Err(ProtocolError::ConflictingLength);
                }
                _ => length = Some(value),
            }
        }
        Ok(length)
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a (String, String);
    type IntoIter = slice::Iter<'a, (String, String)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
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
