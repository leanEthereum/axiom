//! One ssz_snappy payload: a varint length, then a framed snappy stream.

use std::{mem, ops::RangeInclusive};

use axiom_snappy::frame;

use crate::{
    eth::{max_compressed_len, reqresp::ReqRespError},
    varint::{self, Varint, VarintError},
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
        varint::encode(self.0.len() as u64, out);
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
                Err(VarintError::Truncated) => return Ok(None),
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
                max_compressed: max_compressed_len(len) as usize,
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
                    Some(&byte) if byte != STREAM_IDENTIFIER_TYPE => {
                        Err(ReqRespError::MissingStreamIdentifier)
                    }
                    _ => Ok(None),
                };
            }
            if input[0] != STREAM_IDENTIFIER_TYPE {
                return Err(ReqRespError::MissingStreamIdentifier);
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
                    max: max_compressed,
                });
            }
            let Some(chunk) = input.get(..chunk_len) else {
                return Ok(None);
            };
            // Phase 2: decode the chunk as a stream of its own, bounded by the bytes still owed.
            //
            //     [ identifier ][ this chunk ]  → frame decoder, limit = expected - produced
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
