//! Serialization of requests and responses.
//!
//! Bodies are always sent whole with a content length, never chunked.
//! Every message here is built in memory first, so its length is known.
//!
//! ```text
//!     HTTP/1.1 200 OK\r\n
//!     content-type: application/json\r\n     caller's fields, in order
//!     content-length: 2\r\n                  framing, always computed here
//!     \r\n
//!     {}
//! ```

use std::io::Write;

use crate::{
    Headers, HttpError, Method, ProtocolError, Request, Response, StatusCode,
    headers::{is_token_byte, is_value_byte},
};

impl Request {
    /// Serializes the request for a host, such as `localhost:8551`.
    ///
    /// A host field is added when the caller set none, since HTTP/1.1 requires one.
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

        let mut out = Vec::with_capacity(256 + self.body.len());
        // Writes into a vector cannot fail, so the results are discarded.
        let _ = write!(out, "{} {target} HTTP/1.1\r\n", self.method);
        if self.headers.get("host").is_none() {
            write_field(&mut out, "host", host)?;
        }
        write_fields(&mut out, &self.headers)?;

        // A request without a body still states its length when the method expects one.
        // Without it, a server could not tell an empty POST from one still arriving.
        let expects_body = matches!(self.method, Method::Post | Method::Put | Method::Patch);
        if expects_body || !self.body.is_empty() {
            let _ = write!(out, "content-length: {}\r\n", self.body.len());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

impl Response {
    /// Serializes the response.
    ///
    /// A reply to HEAD keeps its length field but drops the body, per RFC 9110 section 9.3.2.
    ///
    /// # Errors
    ///
    /// Fails when a field would corrupt the message.
    pub fn encode(&self, head_only: bool) -> Result<Vec<u8>, HttpError> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        let _ = write!(
            out,
            "HTTP/1.1 {} {}\r\n",
            self.status.as_u16(),
            self.status.reason()
        );
        write_fields(&mut out, &self.headers)?;

        // 1xx and 204 must not carry a length field, per RFC 9110 section 8.6.
        // 304 carries no body either; its length would describe the unsent resource.
        let code = self.status.as_u16();
        let bodiless =
            self.status.is_informational() || self.status == StatusCode::NO_CONTENT || code == 304;
        if !bodiless {
            let _ = write!(out, "content-length: {}\r\n", self.body.len());
        }
        out.extend_from_slice(b"\r\n");
        if !bodiless && !head_only {
            out.extend_from_slice(&self.body);
        }
        Ok(out)
    }
}

/// Writes the caller's fields, leaving framing to the serializer.
///
/// The serializer owns the length, so a stray length or coding field cannot contradict it.
fn write_fields(out: &mut Vec<u8>, headers: &Headers) -> Result<(), HttpError> {
    for (name, value) in headers {
        if name == "content-length" || name == "transfer-encoding" {
            continue;
        }
        write_field(out, name, value)?;
    }
    Ok(())
}

/// Writes one field line after checking it cannot break the framing.
fn write_field(out: &mut Vec<u8>, name: &str, value: &str) -> Result<(), HttpError> {
    // A CR or LF in a value would start a new field: header injection.
    let valid_name = !name.is_empty() && name.bytes().all(is_token_byte);
    let valid_value = value.bytes().all(is_value_byte);
    if !valid_name || !valid_value {
        return Err(HttpError::InvalidHeader);
    }
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{HttpError, Method, Request, Response, StatusCode};

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
}
