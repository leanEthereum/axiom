//! Complete requests and responses, as handlers and callers see them.

use crate::{Headers, HttpError, Method, ProtocolError, StatusCode, wire::Encoder};

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

    /// Whether a connection persists after a message with these fields, per RFC 9112 section 9.3.
    pub(crate) fn persists(self, headers: &Headers) -> bool {
        match self {
            // HTTP/1.1 persists unless a party says close.
            Self::Http11 => !headers.has_token("connection", "close"),
            // HTTP/1.0 closes unless a party asks to keep alive.
            Self::Http10 => headers.has_token("connection", "keep-alive"),
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

    /// Serializes the request for a host, such as `localhost:8551`.
    ///
    /// A host field is added when the caller set none, since HTTP/1.1 requires one.
    /// The body always goes out whole, framed by a content length the encoder computes.
    ///
    /// # Errors
    ///
    /// Fails when the target or a field would corrupt the message.
    pub fn encode(&self, host: &str) -> Result<Vec<u8>, HttpError> {
        // The target must be origin form with no byte that could end the line early.
        let target = self.target();
        if !target.starts_with('/') || !target.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(HttpError::Protocol(ProtocolError::InvalidTarget));
        }

        let mut encoder = Encoder::new(self.body.len());
        encoder.start_line(format_args!("{} {target} HTTP/1.1", self.method));
        if self.headers.get("host").is_none() {
            encoder.field("host", host)?;
        }
        encoder.fields(&self.headers)?;

        // A request without a body still states its length when the method expects one.
        // Without it, a server could not tell an empty POST from one still arriving.
        let expects_body = matches!(self.method, Method::Post | Method::Put | Method::Patch);
        if expects_body || !self.body.is_empty() {
            encoder.content_length(self.body.len());
        }
        Ok(encoder.finish(&self.body))
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

    /// Serializes the response.
    ///
    /// A reply to HEAD keeps its length field but drops the body, per RFC 9110 section 9.3.2.
    ///
    /// # Errors
    ///
    /// Fails when a field would corrupt the message.
    pub fn encode(&self, head_only: bool) -> Result<Vec<u8>, HttpError> {
        let mut encoder = Encoder::new(self.body.len());
        encoder.start_line(format_args!(
            "HTTP/1.1 {} {}",
            self.status.as_u16(),
            self.status.reason()
        ));
        encoder.fields(&self.headers)?;

        // 1xx and 204 must not carry a length field, per RFC 9110 section 8.6.
        // 304 carries no body either; its length would describe the unsent resource.
        let code = self.status.as_u16();
        let bodiless =
            self.status.is_informational() || self.status == StatusCode::NO_CONTENT || code == 304;
        if !bodiless {
            encoder.content_length(self.body.len());
        }
        let body = if bodiless || head_only {
            &[][..]
        } else {
            &self.body
        };
        Ok(encoder.finish(body))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{BodyLength, Limits, RequestHead, ResponseHead};

    #[test]
    fn request_bytes() {
        // A POST with a two-byte JSON body to a host without a caller-set host field.
        let request =
            Request::new(Method::Post, "/rpc?x=1").with_body("application/json", b"{}".to_vec());
        let bytes = request.encode("localhost:8551").unwrap();
        assert_eq!(
            bytes,
            b"POST /rpc?x=1 HTTP/1.1\r\nhost: localhost:8551\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}"
        );
    }

    #[test]
    fn response_bytes() {
        // A caller-set length field is replaced by the computed one.
        let response = Response::new(StatusCode::OK)
            .with_header("content-length", "999")
            .with_body("text/plain", b"ok".to_vec());
        assert_eq!(
            response.encode(false).unwrap(),
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok"
        );

        // A reply to HEAD keeps the length but sends no body.
        assert_eq!(
            response.encode(true).unwrap(),
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\n"
        );

        // 204 has neither length nor body.
        assert_eq!(
            Response::new(StatusCode::NO_CONTENT).encode(false).unwrap(),
            b"HTTP/1.1 204 No Content\r\n\r\n"
        );
    }

    #[test]
    fn injection_is_refused() {
        // A value carrying CRLF would smuggle a second field.
        let response = Response::new(StatusCode::OK).with_header("x", "a\r\nset-cookie: b");
        assert!(matches!(
            response.encode(false),
            Err(HttpError::InvalidHeader)
        ));

        // A target with a space would split the request line.
        let request = Request::new(Method::Get, "/a b");
        assert!(matches!(request.encode("h"), Err(HttpError::Protocol(_))));
    }

    /// Any supported method.
    fn method() -> impl Strategy<Value = Method> {
        prop_oneof![
            Just(Method::Get),
            Just(Method::Head),
            Just(Method::Post),
            Just(Method::Put),
            Just(Method::Delete),
            Just(Method::Options),
            Just(Method::Patch),
        ]
    }

    /// Header fields with token names and values free of control bytes.
    fn fields() -> impl Strategy<Value = Vec<(String, String)>> {
        proptest::collection::vec(("x-[a-z0-9-]{1,12}", "[!-~]([ !-~]{0,20}[!-~])?"), 0..8)
    }

    proptest! {
        #[test]
        fn request_encode_then_parse(
            method in method(),
            path in "/[a-z0-9/_.-]{0,30}",
            query in proptest::option::of("[a-z0-9=&]{0,20}"),
            fields in fields(),
            body in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            // Build the request the way a caller would.
            let target = match &query {
                Some(query) => format!("{path}?{query}"),
                None => path,
            };
            let mut request = Request::new(method, &target);
            for (name, value) in &fields {
                request.headers.append(name, value.as_str());
            }
            request.body = body.clone();

            // Encode, then parse the head back from the bytes.
            let bytes = request.encode("host:1").unwrap();
            let (head, used) = RequestHead::parse(&bytes, &Limits::DEFAULT).unwrap().unwrap();
            prop_assert_eq!(head.method, method);
            prop_assert_eq!(&head.target, &target);
            for (name, value) in &fields {
                prop_assert!(head.headers.get_all(name).any(|v| v == value));
            }

            // The declared length frames exactly the body that was sent.
            let expected = match head.body_length().unwrap() {
                BodyLength::Fixed(length) => length as usize,
                BodyLength::Empty => 0,
                other => panic!("unexpected framing {other:?}"),
            };
            prop_assert_eq!(&bytes[used..], &body[..]);
            prop_assert_eq!(expected, body.len());
        }

        #[test]
        fn response_encode_then_parse(
            code in 200_u16..600,
            fields in fields(),
            body in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let status = StatusCode::new(code).unwrap();
            let mut response = Response::new(status);
            for (name, value) in &fields {
                response.headers.append(name, value.as_str());
            }
            response.body = body.clone();

            // Parse the head back and frame the body from its declared length.
            let bytes = response.encode(false).unwrap();
            let (head, used) = ResponseHead::parse(&bytes, &Limits::DEFAULT).unwrap().unwrap();
            prop_assert_eq!(head.status, status);
            match head.body_length(Method::Get).unwrap() {
                BodyLength::Fixed(length) => {
                    prop_assert_eq!(length as usize, body.len());
                    prop_assert_eq!(&bytes[used..], &body[..]);
                }
                // 204 and 304 carry nothing.
                BodyLength::Empty => prop_assert_eq!(used, bytes.len()),
                other => panic!("unexpected framing {other:?}"),
            }
        }
    }
}
