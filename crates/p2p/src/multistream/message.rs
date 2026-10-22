//! The message framing both sides of a negotiation share.
//!
//! ```text
//! message = [ varint len ][ body ][ '\n' ]     len counts the newline
//! ```

use std::{mem, str};

use super::{MAX_MESSAGE_LEN, NegotiationError, PROTOCOL_HEADER};
use crate::{
    protobuf::{LengthPrefixedDecoder, ProtobufError},
    varint::Varint,
};

/// Reads the messages one side receives, checking the protocol header first.
#[derive(Clone, Debug)]
pub(super) struct MessageReader {
    /// Splits length-prefixed messages off the bytes received.
    frames: LengthPrefixedDecoder,
    /// Whether the peer's header has arrived.
    header_received: bool,
}

impl MessageReader {
    /// A reader that expects the protocol header before any other message.
    pub(super) const fn new() -> Self {
        Self {
            frames: LengthPrefixedDecoder::new(MAX_MESSAGE_LEN),
            header_received: false,
        }
    }

    /// Feeds bytes read from the stream.
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        self.frames.feed(bytes);
    }

    /// The next message after the header, as text, or nothing while it is incomplete.
    pub(super) fn next_text(&mut self) -> Result<Option<&str>, NegotiationError> {
        match self.next_body()? {
            Some(body) => {
                str::from_utf8(body)
                    .map(Some)
                    .map_err(|error| NegotiationError::InvalidUtf8 {
                        valid_up_to: error.valid_up_to(),
                    })
            }
            None => Ok(None),
        }
    }

    /// The next message after the header, as bytes, or nothing while it is incomplete.
    pub(super) fn next_body(&mut self) -> Result<Option<&[u8]>, NegotiationError> {
        // The header arrives first, as text.
        if !self.header_received {
            let Some(header) = self.next_message()? else {
                return Ok(None);
            };
            let header = str::from_utf8(header).map_err(|error| NegotiationError::InvalidUtf8 {
                valid_up_to: error.valid_up_to(),
            })?;
            if header != PROTOCOL_HEADER {
                return Err(NegotiationError::InvalidHeader(header.to_owned()));
            }
            self.header_received = true;
        }
        self.next_message()
    }

    /// Takes the bytes after the last message read, which belong to the negotiated protocol.
    pub(super) fn take_remainder(&mut self) -> Vec<u8> {
        self.frames.take_remainder()
    }

    /// Decodes the body of an `ls` answer back into protocol names.
    ///
    /// ```text
    /// outer body = [ len "/a\n" ][ len "/b\n" ] ...
    /// ```
    pub(super) fn parse_list(body: &[u8]) -> Result<Vec<String>, NegotiationError> {
        // The nested messages carry no header of their own.
        let mut nested = Self {
            frames: LengthPrefixedDecoder::new(MAX_MESSAGE_LEN),
            header_received: true,
        };
        nested.feed(body);
        let mut protocols = Vec::new();
        while let Some(name) = nested.next_text()? {
            protocols.push(name.to_owned());
        }
        // A nested message cut short by the end of the body is malformed.
        // Its full length is unknown, but it needs at least one byte more than remains.
        let remaining = nested.frames.buffered().len();
        if remaining > 0 {
            return Err(NegotiationError::Framing(ProtobufError::Truncated {
                needed: remaining as u64 + 1,
                remaining,
            }));
        }
        Ok(protocols)
    }

    /// The next message body without its newline, header or not.
    fn next_message(&mut self) -> Result<Option<&[u8]>, NegotiationError> {
        let Some(frame) = self.frames.next_frame()? else {
            return Ok(None);
        };
        // Every message ends with a newline, which is not part of the body.
        frame
            .strip_suffix(b"\n")
            .map(Some)
            .ok_or(NegotiationError::MissingNewline { len: frame.len() })
    }
}

/// Queues the messages one side sends.
#[derive(Clone, Debug, Default)]
pub(super) struct MessageWriter {
    /// Bytes waiting to be written.
    out: Vec<u8>,
}

impl MessageWriter {
    /// A writer that opens with the protocol header.
    pub(super) fn with_header() -> Self {
        let mut writer = Self::default();
        writer.push(PROTOCOL_HEADER);
        writer
    }

    /// Queues one text message.
    pub(super) fn push(&mut self, text: &str) {
        self.push_body(text.as_bytes());
    }

    /// Queues an `ls` answer: one message nesting one message per protocol.
    pub(super) fn push_list<'a>(&mut self, protocols: impl IntoIterator<Item = &'a str>) {
        let mut body = Self::default();
        for protocol in protocols {
            body.push(protocol);
        }
        self.push_body(&body.out);
    }

    /// Takes the bytes to write to the stream.
    pub(super) fn take(&mut self) -> Vec<u8> {
        mem::take(&mut self.out)
    }

    /// Queues one message whose body may be arbitrary bytes.
    fn push_body(&mut self, body: &[u8]) {
        // The length counts the trailing newline.
        Varint::Multiformat.write(body.len() as u64 + 1, &mut self.out);
        self.out.extend_from_slice(body);
        self.out.push(b'\n');
    }
}
