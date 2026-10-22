//! Splitting frames off the bytes a session receives.

use super::{FrameType, HEADER_LEN, Header, YamuxError};

/// Splits frames off the bytes received, as they arrive.
///
/// A frame is consumed only once the session has handled it.
/// The session checks a data frame's header before its body arrives.
#[derive(Clone, Debug)]
pub(super) struct FrameReader {
    /// Bytes received, the front of which may belong to frames already handled.
    buffer: Vec<u8>,
    /// Bytes at the front of the buffer already handled.
    consumed: usize,
}

impl FrameReader {
    /// A reader with nothing received.
    pub(super) const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            consumed: 0,
        }
    }

    /// Feeds bytes read from the connection.
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        // Drop every byte of the frames handled, in one move.
        self.buffer.drain(..self.consumed);
        self.consumed = 0;
        self.buffer.extend_from_slice(bytes);
    }

    /// The header of the next frame, once its 12 bytes have arrived.
    pub(super) fn header(&self) -> Result<Option<Header>, YamuxError> {
        let Some((bytes, _)) = self.pending().split_first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        Header::decode(bytes).map(Some)
    }

    /// The body of the next frame, once it has fully arrived.
    ///
    /// Only data frames carry a body; the length of the others means something else.
    pub(super) fn body(&self, header: &Header) -> Option<&[u8]> {
        self.pending()
            .get(HEADER_LEN..HEADER_LEN + Self::body_len(header))
    }

    /// Marks the next frame handled.
    pub(super) const fn consume(&mut self, header: &Header) {
        self.consumed += HEADER_LEN + Self::body_len(header);
    }

    /// Bytes not yet handled.
    fn pending(&self) -> &[u8] {
        &self.buffer[self.consumed..]
    }

    /// Bytes of body that follow a header.
    const fn body_len(header: &Header) -> usize {
        match header.frame_type {
            FrameType::Data => header.length as usize,
            FrameType::WindowUpdate | FrameType::Ping | FrameType::GoAway => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yamux::{Flags, StreamId};

    #[test]
    fn frames_wait_for_their_bytes_and_leave_once_consumed() {
        // A data frame on stream 1 with 3 body bytes, then a ping header.
        let data = Header {
            frame_type: FrameType::Data,
            flags: Flags::SYN,
            stream_id: StreamId(1),
            length: 3,
        };
        let ping = Header {
            frame_type: FrameType::Ping,
            flags: Flags::SYN,
            stream_id: StreamId::SESSION,
            length: 7,
        };
        let mut reader = FrameReader::new();
        // 11 of the 12 header bytes: no header yet.
        reader.feed(&data.encode()[..11]);
        assert_eq!(reader.header(), Ok(None));
        // The whole header, and 2 of the 3 body bytes.
        reader.feed(&[data.encode()[11], b'a', b'b']);
        assert_eq!(reader.header(), Ok(Some(data)));
        assert_eq!(reader.body(&data), None);
        // The last body byte and the ping arrive together.
        let mut rest = vec![b'c'];
        rest.extend_from_slice(&ping.encode());
        reader.feed(&rest);
        assert_eq!(reader.body(&data), Some(&b"abc"[..]));
        // Until consumed, the data frame stays at the front.
        assert_eq!(reader.header(), Ok(Some(data)));
        reader.consume(&data);
        // A ping's length is an opaque value, not a body length.
        assert_eq!(reader.header(), Ok(Some(ping)));
        assert_eq!(reader.body(&ping), Some(&[][..]));
        reader.consume(&ping);
        assert_eq!(reader.header(), Ok(None));
    }

    #[test]
    fn malformed_header_is_reported() {
        // Version 1 is not defined.
        let mut reader = FrameReader::new();
        reader.feed(&[1; HEADER_LEN]);
        assert_eq!(reader.header(), Err(YamuxError::InvalidVersion(1)));
    }
}
