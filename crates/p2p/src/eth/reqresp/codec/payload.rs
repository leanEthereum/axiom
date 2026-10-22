//! One ssz_snappy payload: a varint length, then a framed snappy stream.

use std::{mem, ops::RangeInclusive};

use axiom_snappy::{frame, raw};

use crate::{
    eth::reqresp::ReqRespError,
    varint::{Varint, VarintError},
};

/// Bytes of the stream identifier chunk that opens every framed stream.
const STREAM_IDENTIFIER_LEN: usize = 10;

/// Type byte of the stream identifier chunk.
const STREAM_IDENTIFIER_TYPE: u8 = 0xff;

/// Bytes of a snappy chunk header: a type byte and a 3-byte little-endian length.
const CHUNK_HEADER_LEN: usize = 4;

/// An SSZ payload on its way to the wire.
#[derive(Clone, Copy, Debug)]
pub(in crate::eth::reqresp) struct Payload<'a>(pub(in crate::eth::reqresp) &'a [u8]);

impl Payload<'_> {
    /// Appends the length prefix and the framed snappy stream.
    pub(in crate::eth::reqresp) fn encode_to(self, out: &mut Vec<u8>) {
        Varint::Protobuf.write(self.0.len() as u64, out);
        out.extend_from_slice(&frame::compress(self.0));
    }
}

/// Where a payload decoder stands.
#[derive(Clone, Copy, Debug)]
enum Stage {
    /// Waiting for the length prefix.
    Length,
    /// Reading snappy chunks until the declared length comes out.
    Frames {
        /// The declared SSZ length.
        expected: usize,
        /// The most framed bytes the declared length allows, identifier aside.
        max_compressed: usize,
        /// Framed bytes consumed so far, identifier included.
        framed: usize,
    },
}

/// Decodes one payload as its bytes arrive, consuming only whole units.
///
/// A unit is the length prefix or one snappy chunk.
/// A unit cut short stays in the input until the rest of it arrives.
#[derive(Clone, Debug)]
pub(super) struct PayloadDecoder {
    /// The SSZ lengths accepted.
    bounds: RangeInclusive<u64>,
    /// Progress through the payload.
    stage: Stage,
    /// The SSZ bytes decoded so far.
    out: Vec<u8>,
    /// The stream identifier, then the chunk being decoded.
    ///
    /// The snappy decoder takes whole streams, so each chunk is decoded behind the identifier.
    scratch: Vec<u8>,
}

impl PayloadDecoder {
    /// A decoder of one payload whose SSZ length must fall within bounds.
    pub(super) const fn new(bounds: RangeInclusive<u64>) -> Self {
        Self {
            bounds,
            stage: Stage::Length,
            out: Vec::new(),
            scratch: Vec::new(),
        }
    }

    /// Consumes whole units off the front of the input.
    ///
    /// # Returns
    ///
    /// - The payload, once the declared length has come out.
    /// - Nothing while a unit is incomplete; the input then starts with that unit.
    pub(super) fn advance(&mut self, input: &mut &[u8]) -> Result<Option<Vec<u8>>, ReqRespError> {
        if matches!(self.stage, Stage::Length) {
            // Phase 1: the length prefix, at most 10 bytes, checked before any payload byte is read.
            let mut rest = *input;
            let len = match Varint::Protobuf.read(&mut rest) {
                Ok(len) => len,
                Err(VarintError::Truncated { .. }) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if !self.bounds.contains(&len) {
                return Err(ReqRespError::InvalidLength {
                    len,
                    min: *self.bounds.start(),
                    max: *self.bounds.end(),
                });
            }
            *input = rest;
            // Invariant: len <= bounds.end() <= MAX_PAYLOAD_SIZE, far below usize::MAX.
            let expected = len as usize;
            self.out = Vec::with_capacity(expected.min(1 << 20));
            self.stage = Stage::Frames {
                expected,
                max_compressed: raw::max_compressed_len(expected),
                framed: 0,
            };
        }
        // Phase 2: the framed stream, read chunk by chunk until the declared length comes out.
        self.read_frames(input)
    }

    /// Reads snappy chunks until exactly the declared number of bytes comes out.
    ///
    /// The framing format has no end marker, so the declared length decides where a payload stops.
    fn read_frames(&mut self, input: &mut &[u8]) -> Result<Option<Vec<u8>>, ReqRespError> {
        let Stage::Frames {
            expected,
            max_compressed,
            mut framed,
        } = self.stage
        else {
            return Ok(None);
        };
        // The stream identifier must open the stream.
        if framed == 0 {
            if input.len() < STREAM_IDENTIFIER_LEN {
                return match input.first() {
                    Some(&chunk_type) if chunk_type != STREAM_IDENTIFIER_TYPE => {
                        Err(ReqRespError::MissingStreamIdentifier { chunk_type })
                    }
                    _ => Ok(None),
                };
            }
            if input[0] != STREAM_IDENTIFIER_TYPE {
                return Err(ReqRespError::MissingStreamIdentifier {
                    chunk_type: input[0],
                });
            }
            // The identifier is decoded like any chunk below, which validates its body.
            self.scratch.clear();
            self.scratch
                .extend_from_slice(&input[..STREAM_IDENTIFIER_LEN]);
        }
        loop {
            // Stop once the payload is complete and the leading identifier is consumed.
            if self.out.len() == expected && framed > 0 {
                self.stage = Stage::Length;
                return Ok(Some(mem::take(&mut self.out)));
            }
            // Phase 1: the chunk header.
            let Some(header) = input.get(..CHUNK_HEADER_LEN) else {
                return Ok(None);
            };
            let body_len =
                usize::from(header[1]) | usize::from(header[2]) << 8 | usize::from(header[3]) << 16;
            let chunk_len = CHUNK_HEADER_LEN + body_len;
            // The spec forbids reading past max_compressed_len(n) framed bytes, identifier aside.
            if framed + chunk_len > max_compressed + STREAM_IDENTIFIER_LEN {
                return Err(ReqRespError::CompressedTooLarge {
                    len: framed + chunk_len - STREAM_IDENTIFIER_LEN,
                    max: max_compressed,
                });
            }
            let Some(chunk) = input.get(..chunk_len) else {
                return Ok(None);
            };
            // Phase 2: decode the chunk as a stream of its own, bounded by the bytes still owed.
            //
            //     input = [ identifier ][ this chunk ]
            //     limit = expected - produced
            self.scratch.truncate(STREAM_IDENTIFIER_LEN);
            if framed > 0 {
                self.scratch.extend_from_slice(chunk);
            }
            let decoded = frame::decompress(&self.scratch, expected - self.out.len())?;
            self.out.extend_from_slice(&decoded);
            *input = &input[chunk_len..];
            framed += chunk_len;
            self.stage = Stage::Frames {
                expected,
                max_compressed,
                framed,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_past_the_compressed_bound_is_refused_before_it_arrives() {
        // Fixture state: a payload declared one byte long.
        //
        //     bound = max_compressed_len(1) = 32 + 1 + 1/6 = 33 framed bytes
        let mut decoder = PayloadDecoder::new(1..=100);

        // Mutation: after the stream identifier, a chunk header claims a 1000-byte body.
        //
        //     length prefix   0x01
        //     identifier      0xff 0x06 0x00 0x00 "sNaPpY"
        //     chunk header    0x00 0xe8 0x03 0x00   (1000 bytes, never sent)
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&[0xff, 0x06, 0x00, 0x00]);
        bytes.extend_from_slice(b"sNaPpY");
        bytes.extend_from_slice(&[0x00, 0xe8, 0x03, 0x00]);

        // The header alone is enough to refuse: 4 + 1000 framed bytes exceed the bound of 33.
        let mut input = bytes.as_slice();
        assert_eq!(
            decoder.advance(&mut input),
            Err(ReqRespError::CompressedTooLarge { len: 1004, max: 33 })
        );
    }
}
