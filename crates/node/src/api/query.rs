//! Typed reads of a request's query string and body.
//!
//! A list parameter may repeat, or join its items with commas, or both.
//!
//! ```text
//!     id=1&id=2,3&status=active    id: [1, 2, 3]   status: [active]
//! ```

use std::str::FromStr;

use axiom_beacon_json::ApiJson;
use axiom_http::Request;
use axiom_json::{Data, Json};
use axiom_ssz::Ssz;

use super::{encoding::Encoding, reply::ApiError};

/// The decoded name and value pairs of a request's query string, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Query(Vec<(String, String)>);

impl Query {
    /// The query of a request.
    ///
    /// Percent escapes and the plus sign are decoded.
    /// A malformed escape stays as written, so its value fails the parse that reads it.
    pub(crate) fn of(request: &Request) -> Self {
        let pairs = request
            .query
            .as_deref()
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                (Self::decode(name), Self::decode(value))
            })
            .collect();
        Self(pairs)
    }

    /// The raw value of a parameter.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// A parameter given at most once, parsed.
    ///
    /// # Errors
    ///
    /// Fails with a bad request when the value does not parse.
    pub(crate) fn one<T: FromStr>(&self, name: &str) -> Result<Option<T>, ApiError> {
        self.text(name)
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ApiError::bad_request(format!("invalid {name}: {value}")))
            })
            .transpose()
    }

    /// Every item of a list parameter, in order, as text.
    pub(crate) fn list(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(key, _)| key == name)
            .flat_map(|(_, value)| value.split(','))
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect()
    }

    /// A required decimal parameter.
    pub(crate) fn number(&self, name: &str) -> Result<u64, ApiError> {
        self.optional_number(name)?
            .ok_or_else(|| ApiError::bad_request(format!("missing query parameter {name}")))
    }

    /// An optional decimal parameter.
    pub(crate) fn optional_number(&self, name: &str) -> Result<Option<u64>, ApiError> {
        self.text(name)
            .map(|text| {
                text.parse().map_err(|_| {
                    ApiError::bad_request(format!("query parameter {name} is not a uint64: {text}"))
                })
            })
            .transpose()
    }

    /// A required parameter of fixed-length hex bytes.
    pub(crate) fn bytes<const N: usize>(&self, name: &str) -> Result<[u8; N], ApiError> {
        self.optional_bytes(name)?
            .ok_or_else(|| ApiError::bad_request(format!("missing query parameter {name}")))
    }

    /// An optional parameter of fixed-length hex bytes.
    pub(crate) fn optional_bytes<const N: usize>(
        &self,
        name: &str,
    ) -> Result<Option<[u8; N]>, ApiError> {
        self.text(name)
            .map(|text| {
                <[u8; N]>::from_data(text).map_err(|_| {
                    ApiError::bad_request(format!(
                        "query parameter {name} is not {N} hex bytes: {text}"
                    ))
                })
            })
            .transpose()
    }

    /// Whether a flag parameter is present, with no value or the value true.
    pub(crate) fn flag(&self, name: &str) -> Result<bool, ApiError> {
        match self.text(name) {
            None | Some("false") => Ok(false),
            Some("" | "true") => Ok(true),
            Some(other) => Err(ApiError::bad_request(format!(
                "query parameter {name} is not a boolean: {other}"
            ))),
        }
    }

    /// Undoes percent-encoding and the plus sign for a space, or keeps text it cannot decode.
    fn decode(text: &str) -> String {
        let mut bytes = Vec::with_capacity(text.len());
        let mut input = text.bytes();
        while let Some(byte) = input.next() {
            match byte {
                b'+' => bytes.push(b' '),
                b'%' => {
                    let high = input
                        .next()
                        .and_then(|digit| char::from(digit).to_digit(16));
                    let low = input
                        .next()
                        .and_then(|digit| char::from(digit).to_digit(16));
                    match (high, low) {
                        // Two hex digits make one byte, below 256 by construction.
                        (Some(high), Some(low)) => bytes.push((high * 16 + low) as u8),
                        _ => return text.to_owned(),
                    }
                }
                other => bytes.push(other),
            }
        }
        String::from_utf8(bytes).unwrap_or_else(|_| text.to_owned())
    }
}

/// A request body of JSON or SSZ, decoded into a list of items.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Body<'a>(pub(crate) &'a Request);

impl Body<'_> {
    /// The body as a JSON value.
    pub(crate) fn json(self) -> Result<Json, ApiError> {
        Json::parse(&self.0.body)
            .map_err(|error| ApiError::bad_request(format!("body is not JSON: {error}")))
    }

    /// A JSON array of items, each decoded alone, the failing item named.
    pub(crate) fn json_items<T: ApiJson>(self) -> Result<Vec<T>, ApiError> {
        let value = self.json()?;
        let items = value
            .as_array()
            .ok_or_else(|| ApiError::bad_request("body is not a JSON array"))?;
        items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                T::from_json(item)
                    .map_err(|error| ApiError::bad_request(format!("item {index}: {error}")))
            })
            .collect()
    }

    /// Items from a JSON array, or from SSZ when the body says so.
    ///
    /// An SSZ body of several items is the SSZ list of them, of fixed-size items here.
    pub(crate) fn items<T: ApiJson + Ssz>(self) -> Result<Vec<T>, ApiError> {
        if Encoding::of_body(self.0, true)? == Encoding::Json {
            return self.json_items();
        }
        let size = T::FIXED_SIZE
            .ok_or_else(|| ApiError::unsupported_media_type("application/octet-stream"))?;
        let body = &self.0.body;
        if size == 0 || !body.len().is_multiple_of(size) {
            return Err(ApiError::bad_request(format!(
                "SSZ body of {} bytes is not a list of {size}-byte items",
                body.len()
            )));
        }
        body.chunks(size)
            .map(|chunk| {
                T::decode(chunk)
                    .map_err(|error| ApiError::bad_request(format!("SSZ item: {error}")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use axiom_http::Method;

    use super::*;

    fn query(target: &str) -> Query {
        Query::of(&Request::new(Method::Get, target))
    }

    #[test]
    fn lists_merge_repeats_and_commas() {
        // Two repeats, one holding two items, and an encoded comma.
        let query = query("/v?id=1&id=2,3&id=4%2C5&status=active");
        assert_eq!(query.list("id"), ["1", "2", "3", "4", "5"]);
        assert_eq!(query.list("status"), ["active"]);
        assert_eq!(query.list("absent"), Vec::<&str>::new());
    }

    #[test]
    fn single_values_parse_or_fail() {
        let query = query("/c?epoch=7&slot=x");
        assert_eq!(query.one::<u64>("epoch"), Ok(Some(7)));
        assert_eq!(query.one::<u64>("index"), Ok(None));
        assert_eq!(
            query.one::<u64>("slot"),
            Err(ApiError::bad_request("invalid slot: x"))
        );
    }

    #[test]
    fn broken_percent_encoding_stays_as_written() {
        // A bad escape is kept, so the parse that reads it fails on the original text.
        assert_eq!(query("/v?id=%zz").text("id"), Some("%zz"));
        assert_eq!(query("/v?graffiti=a+b%21").text("graffiti"), Some("a b!"));
    }
}
