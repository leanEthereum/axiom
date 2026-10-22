//! Bodies produced while they are sent, such as a server-sent event stream.
//!
//! A streamed body has no length up front, so it goes out with the chunked transfer coding.
//! Each piece becomes one chunk, and the stream ends with the empty last chunk.
//! See RFC 9112 section 7.1.
//!
//! ```text
//!     5\r\n
//!     hello\r\n
//!     0\r\n
//!     \r\n
//! ```

use std::fmt::Write;

use tokio::sync::mpsc;

/// The receiving end of a body, piece by piece.
///
/// The producer holds a bounded sender, so a slow reader pushes back on it.
/// A producer that cannot wait drops the reader instead, which ends the stream.
#[derive(Debug)]
pub struct BodyStream {
    /// The pieces still to send.
    pieces: mpsc::Receiver<Vec<u8>>,
}

impl BodyStream {
    /// A stream and its sender, buffering up to a number of pieces.
    #[must_use]
    pub fn channel(capacity: usize) -> (mpsc::Sender<Vec<u8>>, Self) {
        let (sender, pieces) = mpsc::channel(capacity);
        (sender, Self { pieces })
    }

    /// The next piece, or nothing once every sender is gone.
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        self.pieces.recv().await
    }

    /// One piece framed as a chunk; an empty piece is skipped, as it would end the stream.
    #[must_use]
    pub fn chunk(piece: &[u8]) -> Vec<u8> {
        if piece.is_empty() {
            return Vec::new();
        }
        let mut size = String::new();
        // Writing to a string cannot fail.
        let _ = write!(size, "{:x}\r\n", piece.len());
        let mut out = Vec::with_capacity(size.len() + piece.len() + 2);
        out.extend_from_slice(size.as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The last chunk, with no trailer fields.
    pub const LAST_CHUNK: &'static [u8] = b"0\r\n\r\n";
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::ChunkedDecoder;

    #[test]
    fn pieces_frame_as_chunks() {
        // Five bytes take one hex digit of size; twenty take two.
        assert_eq!(BodyStream::chunk(b"hello"), b"5\r\nhello\r\n");
        assert_eq!(
            BodyStream::chunk(&[b'x'; 20]),
            [b"14\r\n".as_slice(), &[b'x'; 20], b"\r\n"].concat()
        );

        // An empty piece would read as the last chunk, so it is dropped.
        assert_eq!(BodyStream::chunk(b""), b"");
    }

    proptest! {
        #[test]
        fn framed_pieces_decode_back(pieces in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..8)) {
            // The client's chunked decoder reads back every piece, in order, then the end.
            let mut wire: Vec<u8> = pieces.iter().flat_map(|piece| BodyStream::chunk(piece)).collect();
            wire.extend_from_slice(BodyStream::LAST_CHUNK);
            let mut decoder = ChunkedDecoder::new(1 << 16);
            let mut body = Vec::new();
            let used = decoder.decode(&wire, &mut body).unwrap();
            prop_assert_eq!(used, wire.len());
            prop_assert_eq!(body, pieces.concat());
        }
    }
}
