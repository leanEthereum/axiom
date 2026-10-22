//! Parsing of message heads: the start line and the header fields.
//!
//! ```text
//!     POST /engine HTTP/1.1\r\n          request line
//!     host: localhost:8551\r\n           field line: name ":" OWS value OWS
//!     content-length: 42\r\n
//!     \r\n                               empty line ends the head
//!     {"jsonrpc":"2.0",...}              body, framed by the fields above
//! ```
//!
//! The grammar is RFC 9112 sections 2 to 5.
//! Lines end with CRLF; a bare LF or CR inside the head is rejected.

use crate::{
    BodyLength, Headers, Limits, Method, ProtocolError, StatusCode, Version,
    headers::{is_token_byte, is_value_byte},
};

/// The start line and fields of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    /// The method.
    pub method: Method,

    /// The target in origin form: a path starting with a slash, then an optional query.
    pub target: String,

    /// The protocol version.
    pub version: Version,

    /// The header fields.
    pub headers: Headers,
}

impl RequestHead {
    /// Parses a request head at the start of a buffer.
    ///
    /// Empty lines before the request line are skipped, as RFC 9112 section 2.2 advises.
    ///
    /// # Returns
    ///
    /// The head and the bytes it spans, or nothing while the head is incomplete.
    pub fn parse(buf: &[u8], limits: &Limits) -> Result<Option<(Self, usize)>, ProtocolError> {
        // Skip stray CRLF pairs, which some clients send after a body.
        let mut skipped = 0;
        while buf[skipped..].starts_with(b"\r\n") {
            skipped += 2;
        }
        let Some((lines, length)) = split_head(&buf[skipped..], limits)? else {
            return Ok(None);
        };

        // The request line: method SP target SP version, single spaces only.
        let mut parts = lines.start.split(|&byte| byte == b' ');
        let (Some(method), Some(target), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ProtocolError::InvalidRequestLine);
        };

        // A well-formed token naming no known method earns a 501, anything else a 400.
        let method = match Method::from_bytes(method) {
            Some(method) => method,
            None if !method.is_empty() && method.iter().all(|&byte| is_token_byte(byte)) => {
                return Err(ProtocolError::UnknownMethod);
            }
            None => return Err(ProtocolError::InvalidRequestLine),
        };

        // Origin form only: a slash, then visible ASCII.
        // Absolute form, used toward proxies, and the asterisk form are not served.
        if !target.starts_with(b"/") || !target.iter().all(|&byte| byte.is_ascii_graphic()) {
            return Err(ProtocolError::InvalidTarget);
        }
        // Visible ASCII is valid UTF-8, one byte per character.
        let target = target.iter().copied().map(char::from).collect();

        let version = Version::from_bytes(version).ok_or(ProtocolError::UnsupportedVersion)?;
        let headers = parse_fields(lines.fields, limits)?;

        Ok(Some((
            Self {
                method,
                target,
                version,
                headers,
            },
            skipped + length,
        )))
    }

    /// How the body that follows this head is framed.
    ///
    /// RFC 9112 section 6.3: chunked coding, else a content length, else no body.
    pub fn body_length(&self) -> Result<BodyLength, ProtocolError> {
        Ok(framing(&self.headers)?.unwrap_or(BodyLength::Empty))
    }

    /// Whether the client wants the connection kept open after the response.
    #[must_use]
    pub fn keep_alive(&self) -> bool {
        keep_alive(self.version, &self.headers)
    }
}

/// The status line and fields of a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    /// The protocol version.
    pub version: Version,

    /// The status.
    pub status: StatusCode,

    /// The header fields.
    pub headers: Headers,
}

impl ResponseHead {
    /// Parses a response head at the start of a buffer.
    ///
    /// # Returns
    ///
    /// The head and the bytes it spans, or nothing while the head is incomplete.
    pub fn parse(buf: &[u8], limits: &Limits) -> Result<Option<(Self, usize)>, ProtocolError> {
        let Some((lines, length)) = split_head(buf, limits)? else {
            return Ok(None);
        };

        // The status line: version SP three digits [SP reason].
        //
        //     HTTP/1.1 200 OK
        //     ^^^^^^^^ ^^^ ^^ reason, ignored
        let line = lines.start;
        let Some(space) = line.iter().position(|&byte| byte == b' ') else {
            return Err(ProtocolError::InvalidStatusLine);
        };
        let version =
            Version::from_bytes(&line[..space]).ok_or(ProtocolError::UnsupportedVersion)?;
        let rest = &line[space + 1..];

        // Exactly three digits, then the end of the line or a space and the reason.
        let (code, reason) = rest.split_at(rest.len().min(3));
        let well_formed = code.len() == 3
            && code.iter().all(u8::is_ascii_digit)
            && (reason.is_empty() || reason[0] == b' ')
            && reason.iter().all(|&byte| is_value_byte(byte));
        if !well_formed {
            return Err(ProtocolError::InvalidStatusLine);
        }
        let code = code
            .iter()
            .fold(0_u16, |value, digit| value * 10 + u16::from(digit - b'0'));
        let status = StatusCode::new(code).ok_or(ProtocolError::InvalidStatusLine)?;

        let headers = parse_fields(lines.fields, limits)?;
        Ok(Some((
            Self {
                version,
                status,
                headers,
            },
            length,
        )))
    }

    /// How the body that follows this head is framed.
    ///
    /// RFC 9112 section 6.3, rules 1 to 7:
    ///
    /// ```text
    ///     reply to HEAD, or status 1xx, 204, 304  -> no body
    ///     transfer-encoding: chunked              -> chunked
    ///     content-length: n                       -> n bytes
    ///     neither                                 -> until the server closes
    /// ```
    pub fn body_length(&self, request_method: Method) -> Result<BodyLength, ProtocolError> {
        // These responses never carry a body, whatever their fields claim.
        let code = self.status.as_u16();
        if request_method == Method::Head || self.status.is_informational() || code == 204 {
            return Ok(BodyLength::Empty);
        }
        if code == 304 {
            return Ok(BodyLength::Empty);
        }
        Ok(framing(&self.headers)?.unwrap_or(BodyLength::UntilClose))
    }

    /// Whether the server keeps the connection open after this response.
    #[must_use]
    pub fn keep_alive(&self) -> bool {
        keep_alive(self.version, &self.headers)
    }
}

/// A head split into its start line and its field lines.
struct HeadLines<'a> {
    /// The request line or status line.
    start: &'a [u8],
    /// The field lines, each with its CRLF, and the final CRLF removed.
    fields: &'a [u8],
}

/// Finds the empty line that ends a head.
///
/// # Returns
///
/// The head's lines and its length with the terminator, or nothing while it is incomplete.
fn split_head<'a>(
    buf: &'a [u8],
    limits: &Limits,
) -> Result<Option<(HeadLines<'a>, usize)>, ProtocolError> {
    // Search only within the limit, so a huge buffer costs no more than a full one.
    let window = &buf[..buf.len().min(limits.max_head_bytes)];
    let Some(end) = window.windows(4).position(|four| four == b"\r\n\r\n") else {
        // No terminator yet: wait for more bytes, unless the limit is already reached.
        return if buf.len() >= limits.max_head_bytes {
            Err(ProtocolError::HeadTooLarge)
        } else {
            Ok(None)
        };
    };

    // The start line runs to the first CRLF; fields fill the rest, minus the empty line.
    //
    //     start\r\n field\r\n field\r\n \r\n
    //     ^^^^^     ^^^^^^^^^^^^^^^^^^^^ fields
    let head = &buf[..end + 2];
    let start_end = head
        .windows(2)
        .position(|two| two == b"\r\n")
        .unwrap_or(end);
    Ok(Some((
        HeadLines {
            start: &head[..start_end],
            fields: &head[start_end + 2..],
        },
        end + 4,
    )))
}

/// Parses field lines, each ending with CRLF.
fn parse_fields(mut fields: &[u8], limits: &Limits) -> Result<Headers, ProtocolError> {
    let mut headers = Headers::new();
    while !fields.is_empty() {
        // Each line ends at its CRLF; the head splitter guarantees the last one has it.
        let Some(line_end) = fields.windows(2).position(|two| two == b"\r\n") else {
            return Err(ProtocolError::InvalidHeader);
        };
        let line = &fields[..line_end];
        fields = &fields[line_end + 2..];

        // Count before parsing, so a flood of fields stops at the limit.
        if headers.len() == limits.max_headers {
            return Err(ProtocolError::TooManyHeaders);
        }

        // name ":" OWS value OWS
        //
        // The name must be a nonempty token.
        // That rejects whitespace before the colon and obsolete line folding,
        // as RFC 9112 section 5.1 and 5.2 require of a server.
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            return Err(ProtocolError::InvalidHeader);
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|&byte| is_token_byte(byte)) {
            return Err(ProtocolError::InvalidHeader);
        }

        // Strip optional whitespace around the value, then check what remains.
        let value = value.trim_ascii();
        if !value.iter().all(|&byte| is_value_byte(byte)) {
            return Err(ProtocolError::InvalidHeader);
        }
        // Bytes from 0x80 up are allowed on the wire but must form UTF-8 here.
        let value = str::from_utf8(value).map_err(|_| ProtocolError::InvalidHeader)?;

        // A token is ASCII, so this conversion keeps every byte.
        let name: String = name.iter().copied().map(char::from).collect();
        headers.append(&name, value);
    }
    Ok(headers)
}

/// The framing the fields declare, if any.
///
/// Both declarations at once are refused rather than resolved.
/// RFC 9112 section 6.3 allows that, and it shuts the door on request smuggling.
fn framing(headers: &Headers) -> Result<Option<BodyLength>, ProtocolError> {
    let length = content_length(headers)?;
    let mut codings = headers.get_all("transfer-encoding").peekable();

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
fn content_length(headers: &Headers) -> Result<Option<u64>, ProtocolError> {
    let mut length = None;
    // A field may repeat, and one field may hold a comma-separated list.
    for item in headers
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
            Some(previous) if previous != value => return Err(ProtocolError::ConflictingLength),
            _ => length = Some(value),
        }
    }
    Ok(length)
}

/// Whether a connection persists after the message, per RFC 9112 section 9.3.
fn keep_alive(version: Version, headers: &Headers) -> bool {
    match version {
        // HTTP/1.1 persists unless a party says close.
        Version::Http11 => !headers.has_token("connection", "close"),
        // HTTP/1.0 closes unless a party asks to keep alive.
        Version::Http10 => headers.has_token("connection", "keep-alive"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a complete request head, or returns its error.
    fn request(text: &str) -> Result<RequestHead, ProtocolError> {
        RequestHead::parse(text.as_bytes(), &Limits::DEFAULT)
            .map(|parsed| parsed.expect("head is complete").0)
    }

    #[test]
    fn request_head_with_fields() {
        // Two stray CRLFs, then a 3-line head; consumed bytes include both.
        let text = "\r\n\r\nPOST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-Pad:  v \r\n\r\nBODY";
        let (head, consumed) = RequestHead::parse(text.as_bytes(), &Limits::DEFAULT)
            .unwrap()
            .unwrap();

        // The head stops right before the body.
        assert_eq!(&text[consumed..], "BODY");
        let mut headers = Headers::new();
        headers.append("host", "x");
        headers.append("x-pad", "v");
        assert_eq!(
            head,
            RequestHead {
                method: Method::Post,
                target: "/a?b=1".to_owned(),
                version: Version::Http11,
                headers,
            }
        );
    }

    #[test]
    fn incomplete_head_waits() {
        // No empty line yet, and far below the limit: ask for more bytes.
        let partial = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(RequestHead::parse(partial, &Limits::DEFAULT), Ok(None));
    }

    #[test]
    fn request_line_rejections() {
        // Each malformed request line maps to one error.
        assert_eq!(
            request("BREW / HTTP/1.1\r\n\r\n"),
            Err(ProtocolError::UnknownMethod)
        );
        assert_eq!(
            request("G(T / HTTP/1.1\r\n\r\n"),
            Err(ProtocolError::InvalidRequestLine)
        );
        assert_eq!(
            request("GET  / HTTP/1.1\r\n\r\n"),
            Err(ProtocolError::InvalidRequestLine)
        );
        assert_eq!(
            request("GET http://x/ HTTP/1.1\r\n\r\n"),
            Err(ProtocolError::InvalidTarget)
        );
        assert_eq!(
            request("GET / HTTP/2.0\r\n\r\n"),
            Err(ProtocolError::UnsupportedVersion)
        );
    }

    #[test]
    fn field_rejections() {
        // Space before the colon is a smuggling vector, so RFC 9112 requires a 400.
        assert_eq!(
            request("GET / HTTP/1.1\r\nHost : x\r\n\r\n"),
            Err(ProtocolError::InvalidHeader)
        );
        // Obsolete line folding starts a line with whitespace.
        assert_eq!(
            request("GET / HTTP/1.1\r\nA: b\r\n c\r\n\r\n"),
            Err(ProtocolError::InvalidHeader)
        );
        // A bare LF inside a field value.
        assert_eq!(
            request("GET / HTTP/1.1\r\nA: b\nc\r\n\r\n"),
            Err(ProtocolError::InvalidHeader)
        );
    }

    #[test]
    fn head_and_field_count_limits() {
        // A 20-byte limit cannot hold a 34-byte head.
        let tight = Limits {
            max_head_bytes: 20,
            ..Limits::DEFAULT
        };
        let text = b"GET / HTTP/1.1\r\nHost: abcdefgh\r\n\r\n";
        assert_eq!(
            RequestHead::parse(text, &tight),
            Err(ProtocolError::HeadTooLarge)
        );

        // Two fields against a limit of one.
        let few = Limits {
            max_headers: 1,
            ..Limits::DEFAULT
        };
        let text = b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n";
        assert_eq!(
            RequestHead::parse(text, &few),
            Err(ProtocolError::TooManyHeaders)
        );
    }

    #[test]
    fn request_framing() {
        // Each field set maps to its framing, or to the error that refuses it.
        let cases = [
            ("", Ok(BodyLength::Empty)),
            ("Content-Length: 5\r\n", Ok(BodyLength::Fixed(5))),
            ("Content-Length: 5, 5\r\n", Ok(BodyLength::Fixed(5))),
            (
                "Content-Length: 5\r\nContent-Length: 6\r\n",
                Err(ProtocolError::ConflictingLength),
            ),
            (
                "Content-Length: -1\r\n",
                Err(ProtocolError::InvalidContentLength),
            ),
            ("Transfer-Encoding: Chunked\r\n", Ok(BodyLength::Chunked)),
            (
                "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
                Err(ProtocolError::ConflictingLength),
            ),
            (
                "Transfer-Encoding: gzip, chunked\r\n",
                Err(ProtocolError::UnsupportedTransferEncoding),
            ),
        ];
        for (fields, expected) in cases {
            let head = request(&format!("POST / HTTP/1.1\r\n{fields}\r\n")).unwrap();
            assert_eq!(head.body_length(), expected, "{fields}");
        }
    }

    #[test]
    fn status_line_and_response_framing() {
        // A reply to GET without length fields runs until the server closes.
        let text = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n";
        let (head, consumed) = ResponseHead::parse(text, &Limits::DEFAULT)
            .unwrap()
            .unwrap();
        assert_eq!(consumed, text.len());
        assert_eq!(head.status, StatusCode::OK);
        assert_eq!(head.body_length(Method::Get), Ok(BodyLength::UntilClose));

        // The same head answering HEAD has no body.
        assert_eq!(head.body_length(Method::Head), Ok(BodyLength::Empty));

        // A status line may omit the reason entirely.
        let bare = b"HTTP/1.1 204\r\n\r\n";
        let (head, _) = ResponseHead::parse(bare, &Limits::DEFAULT)
            .unwrap()
            .unwrap();
        assert_eq!(head.status, StatusCode::NO_CONTENT);
        assert_eq!(head.body_length(Method::Get), Ok(BodyLength::Empty));

        // Two-digit codes are malformed.
        assert_eq!(
            ResponseHead::parse(b"HTTP/1.1 20 OK\r\n\r\n", &Limits::DEFAULT),
            Err(ProtocolError::InvalidStatusLine)
        );
    }

    #[test]
    fn persistence_by_version() {
        // HTTP/1.1 persists by default and closes on request.
        assert!(request("GET / HTTP/1.1\r\n\r\n").unwrap().keep_alive());
        assert!(
            !request("GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
                .unwrap()
                .keep_alive()
        );
        // HTTP/1.0 closes by default and persists on request.
        assert!(!request("GET / HTTP/1.0\r\n\r\n").unwrap().keep_alive());
        assert!(
            request("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
                .unwrap()
                .keep_alive()
        );
    }
}
