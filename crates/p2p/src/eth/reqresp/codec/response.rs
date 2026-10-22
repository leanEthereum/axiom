//! Decoding response chunks as they arrive.

use std::mem;

use axiom_types::ForkDigest;

use super::{MAX_ERROR_MESSAGE_LEN, ResponseChunk, ResponseCode, payload::PayloadDecoder};
use crate::eth::reqresp::{Protocol, ReqRespError};

/// Bytes of the fork digest that follows a success code on fork-aware methods.
const CONTEXT_LEN: usize = 4;

/// A response chunk whose code and context have arrived, but not its whole payload.
#[derive(Clone, Debug)]
struct PartialChunk {
    /// The result code.
    code: ResponseCode,
    /// The fork digest, on success chunks of fork-aware methods.
    context: Option<ForkDigest>,
    /// The payload so far.
    payload: PayloadDecoder,
}

/// Decodes response chunks from a stream, as bytes arrive.
#[derive(Clone, Debug)]
pub struct ResponseDecoder {
    /// The method, which fixes context bytes and size bounds.
    protocol: Protocol,
    /// The payload limit.
    max_payload_size: u64,
    /// Bytes received, the front of which may already be decoded.
    buffer: Vec<u8>,
    /// Bytes at the front of the buffer already decoded.
    consumed: usize,
    /// The chunk being decoded.
    chunk: Option<PartialChunk>,
    /// The violation that ended decoding, returned again on every later call.
    failure: Option<ReqRespError>,
    /// Bytes received in all.
    received: usize,
}

impl ResponseDecoder {
    /// A decoder for the responses of one method.
    #[must_use]
    pub const fn new(protocol: Protocol, max_payload_size: u64) -> Self {
        Self {
            protocol,
            max_payload_size,
            buffer: Vec::new(),
            consumed: 0,
            chunk: None,
            failure: None,
            received: 0,
        }
    }

    /// Feeds bytes read from the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        // Drop decoded bytes first, so the buffer holds at most one unit in progress.
        self.buffer.drain(..mem::take(&mut self.consumed));
        self.buffer.extend_from_slice(bytes);
        self.received += bytes.len();
    }

    /// The next complete chunk, or nothing while it is incomplete.
    pub fn next_chunk(&mut self) -> Result<Option<ResponseChunk>, ReqRespError> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        // Decode from the bytes not yet consumed, then record how far decoding got.
        let buffer = mem::take(&mut self.buffer);
        let mut input = &buffer[self.consumed..];
        let result = self.decode(&mut input);
        self.consumed = buffer.len() - input.len();
        self.buffer = buffer;
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }

    /// Checks, at end of stream, that no partial chunk is left.
    pub fn finish(&mut self) -> Result<(), ReqRespError> {
        let partial = self.buffer.len() > self.consumed
            || self.chunk.take().is_some()
            || self.failure.take().is_some();
        self.buffer.clear();
        self.consumed = 0;
        if partial {
            Err(ReqRespError::UnexpectedEof {
                received: self.received,
            })
        } else {
            Ok(())
        }
    }

    /// Decodes as much of one chunk as the input holds.
    fn decode(&mut self, input: &mut &[u8]) -> Result<Option<ResponseChunk>, ReqRespError> {
        let mut chunk = match self.chunk.take() {
            Some(chunk) => chunk,
            None => match self.read_head(input) {
                Some(chunk) => chunk,
                None => return Ok(None),
            },
        };
        // Phase 3: the payload, bounded by its type, or by ErrorMessage for errors.
        match chunk.payload.advance(input) {
            Ok(Some(payload)) => Ok(Some(ResponseChunk {
                code: chunk.code,
                context: chunk.context,
                payload,
            })),
            Ok(None) => {
                self.chunk = Some(chunk);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Reads the result code and context bytes, once both have arrived.
    fn read_head(&self, input: &mut &[u8]) -> Option<PartialChunk> {
        // Phase 1: the result byte.
        let code = ResponseCode::from_byte(*input.first()?);
        let mut head_len = 1;
        // Phase 2: context bytes on success chunks of fork-aware methods.
        let mut context = None;
        if code == ResponseCode::Success && self.protocol.has_context_bytes() {
            let (digest, _) = input.get(1..)?.split_first_chunk::<CONTEXT_LEN>()?;
            context = Some(ForkDigest(*digest));
            head_len += CONTEXT_LEN;
        }
        let bounds = if code == ResponseCode::Success {
            self.protocol.response_bounds(self.max_payload_size)
        } else {
            0..=MAX_ERROR_MESSAGE_LEN as u64
        };
        *input = &input[head_len..];
        Some(PartialChunk {
            code,
            context,
            payload: PayloadDecoder::new(bounds),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn response_chunks_with_context_and_error() {
        let digest = ForkDigest([1, 2, 3, 4]);
        let block = vec![5u8; 300];
        let mut wire = Vec::new();
        ResponseChunk::success(Some(digest), block.clone()).encode_to(&mut wire);
        // Success chunk: [0x00][01 02 03 04][varint 300 = ac 02]...
        assert_eq!(&wire[..7], &[0x00, 1, 2, 3, 4, 0xac, 0x02]);
        ResponseChunk::error(ResponseCode::ResourceUnavailable, "pruned").encode_to(&mut wire);

        // Feed the whole stream one byte at a time.
        let mut decoder = ResponseDecoder::new(Protocol::BeaconBlocksByRangeV2, 10_485_760);
        let mut chunks = Vec::new();
        for byte in wire {
            decoder.feed(&[byte]);
            while let Some(chunk) = decoder.next_chunk().unwrap() {
                chunks.push(chunk);
            }
        }
        assert_eq!(
            chunks,
            [
                ResponseChunk::success(Some(digest), block),
                // Error chunks carry no context, whatever the method.
                ResponseChunk {
                    code: ResponseCode::ResourceUnavailable,
                    context: None,
                    payload: b"pruned".to_vec()
                },
            ]
        );
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn large_payload_spans_several_snappy_chunks() {
        // 200 000 bytes → 4 chunks of at most 65536 uncompressed bytes.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut wire = Vec::new();
        ResponseChunk::success(Some(ForkDigest::ZERO), payload.clone()).encode_to(&mut wire);
        let mut decoder = ResponseDecoder::new(Protocol::BeaconBlocksByRootV2, 10_485_760);
        decoder.feed(&wire);
        assert_eq!(decoder.next_chunk().unwrap().unwrap().payload, payload);
    }

    #[test]
    fn response_bound_is_checked_from_the_header() {
        // A status response claiming 1000 bytes fails before any payload arrives.
        let mut decoder = ResponseDecoder::new(Protocol::StatusV2, 10_485_760);
        decoder.feed(&[0x00, 0xe8, 0x07]);
        let error = ReqRespError::InvalidLength {
            len: 1000,
            min: 92,
            max: 92,
        };
        assert_eq!(decoder.next_chunk(), Err(error.clone()));
        // The violation sticks: a second call reports it again.
        assert_eq!(decoder.next_chunk(), Err(error));
    }

    #[test]
    fn partial_chunk_at_eof() {
        // The code and length arrived, the 8-byte payload did not.
        let mut decoder = ResponseDecoder::new(Protocol::PingV1, 1024);
        decoder.feed(&[0x00, 0x08]);
        assert_eq!(decoder.next_chunk(), Ok(None));
        assert_eq!(
            decoder.finish(),
            Err(ReqRespError::UnexpectedEof { received: 2 })
        );
        // A lone code byte is a partial chunk too.
        let mut decoder = ResponseDecoder::new(Protocol::PingV1, 1024);
        decoder.feed(&[0x00]);
        assert_eq!(decoder.next_chunk(), Ok(None));
        assert_eq!(
            decoder.finish(),
            Err(ReqRespError::UnexpectedEof { received: 1 })
        );
    }

    proptest! {
        #[test]
        fn chunk_round_trip(payload in proptest::collection::vec(any::<u8>(), 100..3000), digest: [u8; 4], cut in 1usize..64) {
            let chunk = ResponseChunk::success(Some(ForkDigest(digest)), payload);
            let mut wire = Vec::new();
            chunk.encode_to(&mut wire);
            chunk.encode_to(&mut wire);
            let mut decoder = ResponseDecoder::new(Protocol::BeaconBlocksByRangeV2, 10_485_760);
            let mut decoded = Vec::new();
            for piece in wire.chunks(cut) {
                decoder.feed(piece);
                while let Some(chunk) = decoder.next_chunk().unwrap() {
                    decoded.push(chunk);
                }
            }
            prop_assert_eq!(decoded, vec![chunk.clone(), chunk]);
            prop_assert_eq!(decoder.finish(), Ok(()));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            for protocol in Protocol::ALL {
                let mut decoder = ResponseDecoder::new(protocol, 10_485_760);
                decoder.feed(&bytes);
                while let Ok(Some(_)) = decoder.next_chunk() {}
            }
        }
    }
}
