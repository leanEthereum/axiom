//! One socket with its read buffer: the bridge from the pure parsers to input and output.

use std::mem;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    BodyLength, ChunkedDecoder, HttpError, Limits, ProtocolError, RequestHead, ResponseHead,
};

/// Bytes requested from the socket per read when the length ahead is unknown.
const READ_CHUNK: usize = 16 << 10;

/// A stream and the bytes read from it but not yet parsed.
///
/// The buffer may hold the start of the next message after the current one ends.
/// Every read appends to the buffer through spare capacity.
/// A read cancelled by a timeout therefore never leaves garbage behind.
#[derive(Debug)]
pub(crate) struct Connection<S> {
    /// The socket.
    stream: S,
    /// Read but unparsed bytes.
    buf: Vec<u8>,
    /// Bounds on what the peer may send.
    limits: Limits,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Wraps a fresh stream.
    pub(crate) const fn new(stream: S, limits: Limits) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            limits,
        }
    }

    /// Whether bytes past the last message are waiting in the buffer.
    pub(crate) const fn has_buffered(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Reads a request head.
    ///
    /// # Returns
    ///
    /// The head, or nothing when the peer closed cleanly between requests.
    pub(crate) async fn read_request_head(&mut self) -> Result<Option<RequestHead>, HttpError> {
        loop {
            // Try the bytes at hand before asking the socket for more.
            if let Some((head, used)) = RequestHead::parse(&self.buf, &self.limits)? {
                self.buf.drain(..used);
                return Ok(Some(head));
            }
            if self.fill(READ_CHUNK).await? == 0 {
                // End of stream: clean between messages, truncated inside one.
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ProtocolError::UnexpectedEof.into())
                };
            }
        }
    }

    /// Reads a response head.
    pub(crate) async fn read_response_head(&mut self) -> Result<ResponseHead, HttpError> {
        loop {
            if let Some((head, used)) = ResponseHead::parse(&self.buf, &self.limits)? {
                self.buf.drain(..used);
                return Ok(head);
            }
            if self.fill(READ_CHUNK).await? == 0 {
                // No byte at all means the server dropped the connection before answering.
                return Err(if self.buf.is_empty() {
                    HttpError::Closed
                } else {
                    ProtocolError::UnexpectedEof.into()
                });
            }
        }
    }

    /// Reads a body framed as the head declared.
    pub(crate) async fn read_body(&mut self, length: BodyLength) -> Result<Vec<u8>, HttpError> {
        let max = self.limits.max_body_bytes;
        match length {
            BodyLength::Empty => Ok(Vec::new()),
            BodyLength::Fixed(length) => {
                // Refuse an oversized body from its declared length, before reading any of it.
                let length = usize::try_from(length)
                    .ok()
                    .filter(|&length| length <= max)
                    .ok_or(ProtocolError::BodyTooLarge)?;
                // The length is known, so one reservation covers the whole read.
                while self.buf.len() < length {
                    if self.fill(length - self.buf.len()).await? == 0 {
                        return Err(ProtocolError::UnexpectedEof.into());
                    }
                }
                // Split off whatever follows the body; it belongs to the next message.
                let rest = self.buf.split_off(length);
                Ok(mem::replace(&mut self.buf, rest))
            }
            BodyLength::Chunked => {
                let mut decoder = ChunkedDecoder::new(max);
                let mut body = Vec::new();
                loop {
                    // Decode what is buffered, then drop exactly the bytes the body used.
                    let used = decoder.decode(&self.buf, &mut body)?;
                    self.buf.drain(..used);
                    if decoder.is_done() {
                        return Ok(body);
                    }
                    if self.fill(READ_CHUNK).await? == 0 {
                        return Err(ProtocolError::UnexpectedEof.into());
                    }
                }
            }
            BodyLength::UntilClose => loop {
                // The body is everything until end of stream, within the bound.
                if self.buf.len() > max {
                    return Err(ProtocolError::BodyTooLarge.into());
                }
                if self.fill(READ_CHUNK).await? == 0 {
                    return Ok(mem::take(&mut self.buf));
                }
            },
        }
    }

    /// Writes bytes and flushes them.
    pub(crate) async fn write(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Appends up to a number of bytes from the socket to the buffer.
    ///
    /// # Returns
    ///
    /// The bytes read, zero at end of stream.
    async fn fill(&mut self, wanted: usize) -> Result<usize, HttpError> {
        // Reading into spare capacity is cancel-safe: the length grows only with real data.
        self.buf.reserve(wanted.max(1));
        Ok(self.stream.read_buf(&mut self.buf).await?)
    }
}
