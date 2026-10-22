//! Typed reads of a request's query string and body, as the validator routes take them.

use axiom_beacon_json::ApiJson;
use axiom_http::Request;
use axiom_json::{Data, Json};
use axiom_ssz::{ProgressiveList, Ssz};

use super::reply::{ApiError, Reply};

/// The name and value pairs of a request's query string.
///
/// Values the validator routes take are numbers and hex strings, which need no unescaping.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Query(Vec<(String, String)>);

impl Query {
    /// The query of a request.
    pub(crate) fn of(request: &Request) -> Self {
        let pairs = request
            .query
            .as_deref()
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((name, value)) => (name.to_owned(), value.to_owned()),
                None => (pair.to_owned(), String::new()),
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

    /// Every value of a parameter given several times, or once with commas between values.
    ///
    /// ```text
    ///     id=1&id=0xa1b2...   or   id=1,0xa1b2...   or   id=1%2C0xa1b2...
    /// ```
    pub(crate) fn list(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(key, _)| key == name)
            // A comma is the only escape these values contain, in either case.
            .map(|(_, value)| value.replace("%2C", ",").replace("%2c", ","))
            .flat_map(|value| {
                value
                    .split(',')
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
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

    /// A single JSON object of a type.
    pub(crate) fn json_item<T: ApiJson>(self) -> Result<T, ApiError> {
        T::from_json(&self.json()?).map_err(|error| ApiError::bad_request(error.to_string()))
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
    /// An SSZ body of several items is the SSZ list of them.
    /// A list encodes the same whatever its limit, so an unbounded list reads any of them.
    /// The server's body limit bounds the count.
    pub(crate) fn items<T: ApiJson + Ssz>(self) -> Result<Vec<T>, ApiError> {
        if !Reply::sends_ssz(self.0) {
            return self.json_items();
        }
        ProgressiveList::<T>::decode(&self.0.body)
            .map(ProgressiveList::into_vec)
            .map_err(|error| ApiError::bad_request(format!("SSZ body: {error}")))
    }
}
