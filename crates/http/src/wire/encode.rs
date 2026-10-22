//! The byte writer behind request and response serialization.
//!
//! Bodies held whole are sent with a content length.
//! A streamed body's head announces the chunked coding, and its chunks follow separately.
//!
//! ```text
//!     HTTP/1.1 200 OK\r\n
//!     content-type: application/json\r\n     caller's fields, in order
//!     content-length: 2\r\n                  framing, always computed here
//!     \r\n
//!     {}
//! ```

use std::{fmt, io::Write};

use crate::{Headers, HttpError, charset::Charset};

/// Room reserved for the start line and fields, ahead of the body.
///
/// Engine API and beacon API heads stay well below it, so one allocation serves most messages.
const HEAD_CAPACITY: usize = 256;

/// Writes one message, line by line, into a buffer sized for its body.
#[derive(Debug)]
pub(crate) struct Encoder {
    /// The bytes written so far.
    out: Vec<u8>,
}

impl Encoder {
    /// An empty message with room for a head and a body of this many bytes.
    pub(crate) fn new(body_len: usize) -> Self {
        Self {
            out: Vec::with_capacity(HEAD_CAPACITY + body_len),
        }
    }

    /// Writes the request line or status line, then its CRLF.
    ///
    /// The caller checks the line holds no byte that could end it early.
    pub(crate) fn start_line(&mut self, line: fmt::Arguments<'_>) {
        // Writes into a vector cannot fail, so the results are discarded.
        let _ = self.out.write_fmt(line);
        self.out.extend_from_slice(b"\r\n");
    }

    /// Writes the caller's fields, leaving framing to the encoder.
    ///
    /// The encoder owns the length, so a stray length or coding field cannot contradict it.
    pub(crate) fn fields(&mut self, headers: &Headers) -> Result<(), HttpError> {
        for (name, value) in headers {
            if name == "content-length" || name == "transfer-encoding" {
                continue;
            }
            self.field(name, value)?;
        }
        Ok(())
    }

    /// Writes one field line after checking it cannot break the framing.
    pub(crate) fn field(&mut self, name: &str, value: &str) -> Result<(), HttpError> {
        // A CR or LF in a value would start a new field: header injection.
        let valid_name = !name.is_empty() && Charset::Token.admits(name.as_bytes());
        let valid_value = Charset::FieldValue.admits(value.as_bytes());
        if !valid_name || !valid_value {
            return Err(HttpError::InvalidHeader {
                name: name.to_owned(),
            });
        }
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(b": ");
        self.out.extend_from_slice(value.as_bytes());
        self.out.extend_from_slice(b"\r\n");
        Ok(())
    }

    /// Writes the chunked transfer coding field, for a body of unknown length.
    pub(crate) fn chunked(&mut self) {
        self.out
            .extend_from_slice(b"transfer-encoding: chunked\r\n");
    }

    /// Writes the content length field, for a body held whole.
    pub(crate) fn content_length(&mut self, len: usize) {
        let _ = write!(self.out, "content-length: {len}\r\n");
    }

    /// Ends the head with its empty line and appends the body.
    pub(crate) fn finish(mut self, body: &[u8]) -> Vec<u8> {
        self.out.extend_from_slice(b"\r\n");
        self.out.extend_from_slice(body);
        self.out
    }
}
