//! Complete requests and responses, as handlers and callers see them.

use crate::{Headers, Method, StatusCode};

/// The protocol version on a start line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.0, where connections close after one exchange unless asked otherwise.
    Http10,

    /// HTTP/1.1, where connections persist unless asked otherwise.
    Http11,
}

impl Version {
    /// The version as written on a start line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }

    /// Reads a version token; only the two HTTP/1 versions are known.
    #[must_use]
    pub const fn from_bytes(token: &[u8]) -> Option<Self> {
        match token {
            b"HTTP/1.0" => Some(Self::Http10),
            b"HTTP/1.1" => Some(Self::Http11),
            _ => None,
        }
    }
}

/// A request with its whole body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,

    /// The path, still percent-encoded, without the query.
    pub path: String,

    /// The text after the question mark, when the target has one.
    pub query: Option<String>,

    /// The header fields.
    pub headers: Headers,

    /// The decoded body, empty when the request has none.
    pub body: Vec<u8>,

    /// Values the router captured from the path, in pattern order.
    pub params: Vec<(String, String)>,
}

impl Request {
    /// A request without fields or body, for a target such as `/eth/v1/node/health?x=1`.
    #[must_use]
    pub fn new(method: Method, target: &str) -> Self {
        // The first question mark splits the path from the query, per RFC 3986 section 3.4.
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query.to_owned())),
            None => (target, None),
        };
        Self {
            method,
            path: path.to_owned(),
            query,
            headers: Headers::new(),
            body: Vec::new(),
            params: Vec::new(),
        }
    }

    /// Adds a header field.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Sets the body and its media type.
    #[must_use]
    pub fn with_body(mut self, content_type: &str, body: Vec<u8>) -> Self {
        self.headers.insert("content-type", content_type);
        self.body = body;
        self
    }

    /// The value the router captured for a named path segment.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The target as sent on the request line, path then query.
    #[must_use]
    pub fn target(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }
}

/// A response with its whole body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status.
    pub status: StatusCode,

    /// The header fields.
    pub headers: Headers,

    /// The decoded body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response without fields or body.
    #[must_use]
    pub const fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    /// Adds a header field.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Sets the body and its media type.
    #[must_use]
    pub fn with_body(mut self, content_type: &str, body: Vec<u8>) -> Self {
        self.headers.insert("content-type", content_type);
        self.body = body;
        self
    }
}
