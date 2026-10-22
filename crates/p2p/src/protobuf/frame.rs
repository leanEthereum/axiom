//! Splitting varint-length-prefixed frames off a byte stream.

use std::mem;

use super::ProtobufError;
use crate::varint::{Varint, VarintError};

/// Splits varint-length-prefixed frames off a byte stream, as bytes arrive.
///
/// ```text
/// stream = [ varint len ][ len bytes ][ varint len ][ len bytes ] ...
/// ```
///
/// The prefix follows the multiformats rules: at most nine bytes, minimally encoded.
#[derive(Clone, Debug)]
pub struct LengthPrefixedDecoder {
    /// Longest frame body accepted.
    max_len: usize,
    /// Bytes received, the front of which may belong to the frame last returned.
    buffer: Vec<u8>,
    /// Bytes at the front of the buffer already handed out as a frame.
    consumed: usize,
}

impl LengthPrefixedDecoder {
    /// A decoder accepting frames of at most a given body length.
    #[must_use]
    pub const fn new(max_len: usize) -> Self {
        Self {
            max_len,
            buffer: Vec::new(),
            consumed: 0,
        }
    }

    /// Feeds bytes read from the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.compact();
        self.buffer.extend_from_slice(bytes);
    }

    /// The body of the next complete frame, or nothing while it is incomplete.
    ///
    /// # Errors
    ///
    /// Fails on a malformed prefix or a declared length above the bound.
    /// The bound is checked before waiting for the body, so a peer cannot make the reader buffer it.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, ProtobufError> {
        // The frame returned last is no longer borrowed: drop it.
        self.compact();
        let mut rest = &self.buffer[..];
        let len = match Varint::Multiformat.read(&mut rest) {
            Ok(len) => len,
            // A prefix cut short waits for more bytes.
            Err(VarintError::Truncated) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let prefix = self.buffer.len() - rest.len();
        // Reject an oversized frame as soon as its header arrives.
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > self.max_len {
            return Err(ProtobufError::FrameTooLarge {
                len,
                max: self.max_len,
            });
        }
        // Wait until the whole body is buffered.
        let end = prefix + len;
        if self.buffer.len() < end {
            return Ok(None);
        }
        self.consumed = end;
        Ok(Some(&self.buffer[prefix..end]))
    }

    /// Bytes received but not yet handed out as a frame.
    #[must_use]
    pub fn buffered(&self) -> &[u8] {
        &self.buffer[self.consumed..]
    }

    /// Takes the bytes not yet handed out, leaving the decoder empty.
    ///
    /// After a protocol switch, those bytes belong to the next protocol.
    pub fn take_remainder(&mut self) -> Vec<u8> {
        self.compact();
        mem::take(&mut self.buffer)
    }

    /// Drops the bytes of the frame last returned.
    fn compact(&mut self) {
        if self.consumed > 0 {
            self.buffer.drain(..mem::take(&mut self.consumed));
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn frames_arrive_whole_or_wait() {
        // A 3-byte body behind a 1-byte prefix, then one byte of the next frame.
        let mut decoder = LengthPrefixedDecoder::new(16);
        // Only 2 of the 3 body bytes arrived.
        decoder.feed(&[0x03, 7, 8]);
        assert_eq!(decoder.next_frame(), Ok(None));
        decoder.feed(&[9, 0xaa]);
        assert_eq!(decoder.next_frame(), Ok(Some(&[7u8, 8, 9][..])));
        // The byte after the frame stays buffered for the next protocol.
        assert_eq!(decoder.buffered(), [0xaa]);
        assert_eq!(decoder.take_remainder(), [0xaa]);
        assert_eq!(decoder.buffered(), []);
    }

    #[test]
    fn bound_is_checked_from_the_header() {
        // A bound of 2 rejects a 3-byte frame before its body arrives.
        let mut decoder = LengthPrefixedDecoder::new(2);
        decoder.feed(&[0x03]);
        assert_eq!(
            decoder.next_frame(),
            Err(ProtobufError::FrameTooLarge { len: 3, max: 2 })
        );
    }

    #[test]
    fn prefix_follows_the_multiformats_rules() {
        // [0x80, 0x00] is a redundant encoding of zero.
        let mut decoder = LengthPrefixedDecoder::new(16);
        decoder.feed(&[0x80, 0x00]);
        assert_eq!(
            decoder.next_frame(),
            Err(ProtobufError::Varint(VarintError::NotMinimal))
        );
        // A prefix cut short waits.
        let mut decoder = LengthPrefixedDecoder::new(16);
        decoder.feed(&[0x80]);
        assert_eq!(decoder.next_frame(), Ok(None));
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut decoder = LengthPrefixedDecoder::new(32);
            decoder.feed(&bytes);
            while let Ok(Some(_)) = decoder.next_frame() {}
        }

        #[test]
        fn any_split_yields_the_same_frames(
            bodies in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 0..6),
            cut in 1usize..32,
        ) {
            // Frame every body, then feed the stream in pieces of cut bytes.
            let mut wire = Vec::new();
            for body in &bodies {
                Varint::Multiformat.write(body.len() as u64, &mut wire);
                wire.extend_from_slice(body);
            }
            let mut decoder = LengthPrefixedDecoder::new(256);
            let mut frames = Vec::new();
            for piece in wire.chunks(cut) {
                decoder.feed(piece);
                while let Some(frame) = decoder.next_frame().unwrap() {
                    frames.push(frame.to_vec());
                }
            }
            prop_assert_eq!(frames, bodies);
            prop_assert_eq!(decoder.buffered(), &[] as &[u8]);
        }
    }
}
