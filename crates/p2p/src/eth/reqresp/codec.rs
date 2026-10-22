//! The ssz_snappy wire format of requests and response chunks.
//!
//! # Overview
//!
//! ```text
//! request         = [ varint ssz_len ][ snappy frames ]
//! response chunk  = [ result: 1 byte ][ context: 4 bytes, success only ][ varint ssz_len ][ snappy frames ]
//!
//! snappy frames   = [ ff 06 00 00 "sNaPpY" ][ chunk ][ chunk ] ...   at most 64 KiB per chunk
//! ```
//!
//! The varint is the uncompressed SSZ length, checked against the type's bounds before any read.
//! A reader takes at most max_compressed_len(n) framed bytes for n SSZ bytes.
//! See `specs/phase0/p2p-interface.md`, SSZ-snappy encoding strategy.

use std::{mem, ops::RangeInclusive};

use axiom_snappy::frame;
use axiom_types::ForkDigest;

use super::{Protocol, ReqRespError};
use crate::{eth::max_compressed_len, varint};

/// Bytes of the stream identifier chunk that opens every framed stream.
const STREAM_IDENTIFIER_LEN: usize = 10;

/// Type byte of the stream identifier chunk.
const STREAM_IDENTIFIER_TYPE: u8 = 0xff;

/// Bytes of a snappy chunk header: a type byte and a 3-byte little-endian length.
const CHUNK_HEADER_LEN: usize = 4;

/// Longest error message, the ErrorMessage list bound.
pub const MAX_ERROR_MESSAGE_LEN: usize = 256;

/// The result byte opening every response chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseCode {
    /// A payload of the expected type follows.
    Success,
    /// The request was malformed or semantically invalid.
    InvalidRequest,
    /// The responder failed while processing.
    ServerError,
    /// The responder does not have the requested resource.
    ResourceUnavailable,
    /// A code in 4..=127, reserved and to be treated as an error.
    Reserved(u8),
    /// A code in 128..=255, a client-specific error.
    ClientSpecific(u8),
}

impl ResponseCode {
    /// The wire byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::InvalidRequest => 1,
            Self::ServerError => 2,
            Self::ResourceUnavailable => 3,
            Self::Reserved(code) | Self::ClientSpecific(code) => code,
        }
    }

    /// The code a wire byte names.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Success,
            1 => Self::InvalidRequest,
            2 => Self::ServerError,
            3 => Self::ResourceUnavailable,
            4..=127 => Self::Reserved(byte),
            _ => Self::ClientSpecific(byte),
        }
    }
}

/// One decoded or to-be-encoded response chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseChunk {
    /// The result code.
    pub code: ResponseCode,
    /// The fork digest of the payload, for methods with ForkDigest-context.
    pub context: Option<ForkDigest>,
    /// The SSZ payload, or the error message bytes for an error code.
    pub payload: Vec<u8>,
}

impl ResponseChunk {
    /// A success chunk.
    #[must_use]
    pub const fn success(context: Option<ForkDigest>, payload: Vec<u8>) -> Self {
        Self {
            code: ResponseCode::Success,
            context,
            payload,
        }
    }

    /// An error chunk with a message, truncated to 256 bytes.
    #[must_use]
    pub fn error(code: ResponseCode, message: &str) -> Self {
        let mut payload = message.as_bytes().to_vec();
        payload.truncate(MAX_ERROR_MESSAGE_LEN);
        Self {
            code,
            context: None,
            payload,
        }
    }
}

/// Encodes a request: length prefix and framed payload, or nothing for empty requests.
#[must_use]
pub fn encode_request(protocol: Protocol, ssz: &[u8]) -> Vec<u8> {
    // Methods without request content send no bytes at all.
    if protocol.has_empty_request() {
        return Vec::new();
    }
    let mut out = Vec::new();
    encode_payload(ssz, &mut out);
    out
}

/// Decodes a complete request, read until the requester closed its side.
///
/// # Errors
///
/// Any violation means the responder answers with an invalid-request error.
pub fn decode_request(
    protocol: Protocol,
    bytes: &[u8],
    max_payload_size: u64,
) -> Result<Vec<u8>, ReqRespError> {
    if protocol.has_empty_request() {
        return if bytes.is_empty() {
            Ok(Vec::new())
        } else {
            Err(ReqRespError::TrailingBytes)
        };
    }
    let bounds = protocol.request_bounds();
    let bounds = *bounds.start()..=(*bounds.end()).min(max_payload_size);
    match decode_payload(bytes, &bounds)? {
        Some((payload, consumed)) if consumed == bytes.len() => Ok(payload),
        // Bytes after the declared length must not exist: EOF was expected.
        Some(_) => Err(ReqRespError::TrailingBytes),
        // The stream closed before the declared length arrived.
        None => Err(ReqRespError::UnexpectedEof),
    }
}

/// Appends one response chunk.
pub fn encode_response_chunk(chunk: &ResponseChunk, out: &mut Vec<u8>) {
    out.push(chunk.code.to_byte());
    // Context bytes accompany success chunks only; error chunks never carry them.
    if chunk.code == ResponseCode::Success
        && let Some(digest) = chunk.context
    {
        out.extend_from_slice(digest.as_bytes());
    }
    encode_payload(&chunk.payload, out);
}

/// Appends a length prefix and a framed snappy stream.
fn encode_payload(ssz: &[u8], out: &mut Vec<u8>) {
    varint::encode(ssz.len() as u64, out);
    out.extend_from_slice(&frame::compress(ssz));
}

/// Decodes a length prefix and the framed payload it announces.
///
/// # Returns
///
/// The payload and the bytes consumed, or nothing while more input is needed.
fn decode_payload(
    bytes: &[u8],
    bounds: &RangeInclusive<u64>,
) -> Result<Option<(Vec<u8>, usize)>, ReqRespError> {
    // Phase 1: the length prefix, at most 10 bytes, checked before any payload byte is read.
    let Some((len, prefix_len)) = varint::decode(bytes)? else {
        return Ok(None);
    };
    if !bounds.contains(&len) {
        return Err(ReqRespError::InvalidLength {
            len,
            min: *bounds.start(),
            max: *bounds.end(),
        });
    }
    // Invariant: len <= bounds.end() <= MAX_PAYLOAD_SIZE, far below usize::MAX.
    let len = len as usize;
    // Phase 2: the framed stream, read chunk by chunk until len bytes come out.
    let max_compressed = max_compressed_len(len as u64) as usize;
    match decode_frames(&bytes[prefix_len..], len, max_compressed)? {
        Some((payload, consumed)) => Ok(Some((payload, prefix_len + consumed))),
        None => Ok(None),
    }
}

/// Reads snappy chunks until exactly a number of uncompressed bytes come out.
///
/// The framing format has no end marker, so the declared length decides where a payload stops.
fn decode_frames(
    bytes: &[u8],
    expected: usize,
    max_compressed: usize,
) -> Result<Option<(Vec<u8>, usize)>, ReqRespError> {
    // The stream identifier must open the stream.
    if bytes.len() < STREAM_IDENTIFIER_LEN {
        return match bytes.first() {
            Some(&byte) if byte != STREAM_IDENTIFIER_TYPE => {
                Err(ReqRespError::MissingStreamIdentifier)
            }
            _ => Ok(None),
        };
    }
    if bytes[0] != STREAM_IDENTIFIER_TYPE {
        return Err(ReqRespError::MissingStreamIdentifier);
    }
    let mut out = Vec::with_capacity(expected.min(1 << 20));
    let mut offset = 0;
    // The identifier itself is decoded like any chunk below, which validates its body.
    let mut chunk_buffer = Vec::new();
    loop {
        // Stop once the payload is complete and the leading identifier is consumed.
        if out.len() == expected && offset > 0 {
            return Ok(Some((out, offset)));
        }
        // Phase 1: the chunk header.
        let Some(header) = bytes.get(offset..offset + CHUNK_HEADER_LEN) else {
            return Ok(None);
        };
        let body_len =
            usize::from(header[1]) | usize::from(header[2]) << 8 | usize::from(header[3]) << 16;
        let end = offset + CHUNK_HEADER_LEN + body_len;
        // The spec forbids reading past max_compressed_len(n) framed bytes, identifier aside.
        if end > max_compressed + STREAM_IDENTIFIER_LEN {
            return Err(ReqRespError::CompressedTooLarge {
                max: max_compressed,
            });
        }
        let Some(chunk) = bytes.get(offset..end) else {
            return Ok(None);
        };
        // Phase 2: decode the chunk as a stream of its own, bounded by the bytes still owed.
        //
        //     [ identifier ][ this chunk ]  → frame decoder, limit = expected - produced
        chunk_buffer.clear();
        chunk_buffer.extend_from_slice(&bytes[..STREAM_IDENTIFIER_LEN]);
        if offset > 0 {
            chunk_buffer.extend_from_slice(chunk);
        }
        let decoded = frame::decompress(&chunk_buffer, expected - out.len())?;
        out.extend_from_slice(&decoded);
        offset = end;
    }
}

/// Decodes response chunks from a stream, as bytes arrive.
#[derive(Clone, Debug)]
pub struct ResponseDecoder {
    /// The method, which fixes context bytes and size bounds.
    protocol: Protocol,
    /// The payload limit.
    max_payload_size: u64,
    /// Bytes received but not yet decoded.
    buffer: Vec<u8>,
}

impl ResponseDecoder {
    /// A decoder for the responses of one method.
    #[must_use]
    pub const fn new(protocol: Protocol, max_payload_size: u64) -> Self {
        Self {
            protocol,
            max_payload_size,
            buffer: Vec::new(),
        }
    }

    /// Feeds bytes read from the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next complete chunk, or nothing while it is incomplete.
    pub fn next_chunk(&mut self) -> Result<Option<ResponseChunk>, ReqRespError> {
        // Phase 1: the result byte.
        let Some(&code) = self.buffer.first() else {
            return Ok(None);
        };
        let code = ResponseCode::from_byte(code);
        let mut offset = 1;
        // Phase 2: context bytes on success chunks of fork-aware methods.
        let mut context = None;
        if code == ResponseCode::Success && self.protocol.has_context_bytes() {
            let Some(digest) = self.buffer.get(offset..offset + 4) else {
                return Ok(None);
            };
            context = Some(ForkDigest([digest[0], digest[1], digest[2], digest[3]]));
            offset += 4;
        }
        // Phase 3: the payload, bounded by its type, or by ErrorMessage for errors.
        let bounds = if code == ResponseCode::Success {
            self.protocol.response_bounds(self.max_payload_size)
        } else {
            0..=MAX_ERROR_MESSAGE_LEN as u64
        };
        let Some((payload, consumed)) = decode_payload(&self.buffer[offset..], &bounds)? else {
            return Ok(None);
        };
        self.buffer.drain(..offset + consumed);
        Ok(Some(ResponseChunk {
            code,
            context,
            payload,
        }))
    }

    /// Checks, at end of stream, that no partial chunk is left.
    pub fn finish(&mut self) -> Result<(), ReqRespError> {
        if mem::take(&mut self.buffer).is_empty() {
            Ok(())
        } else {
            Err(ReqRespError::UnexpectedEof)
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn request_layout() {
        // A Goodbye request: uint64 reason 1, SSZ = 8 bytes little-endian.
        let ssz = 1u64.to_le_bytes();
        let wire = encode_request(Protocol::GoodbyeV1, &ssz);
        // [0x08 length][ff 06 00 00 sNaPpY][chunk]
        assert_eq!(wire[0], 0x08);
        assert_eq!(
            &wire[1..11],
            &[0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y']
        );
        assert_eq!(
            decode_request(Protocol::GoodbyeV1, &wire, 10_485_760),
            Ok(ssz.to_vec())
        );
    }

    #[test]
    fn metadata_request_is_empty() {
        assert_eq!(encode_request(Protocol::MetaDataV3, &[]), Vec::<u8>::new());
        assert_eq!(decode_request(Protocol::MetaDataV3, &[], 1024), Ok(vec![]));
        assert_eq!(
            decode_request(Protocol::MetaDataV3, &[0], 1024),
            Err(ReqRespError::TrailingBytes)
        );
    }

    #[test]
    fn request_violations() {
        let ssz = [7u8; 8];
        let wire = encode_request(Protocol::PingV1, &ssz);
        // Mutation: declare 9 bytes for a type of exactly 8.
        let mut wrong = wire.clone();
        wrong[0] = 9;
        assert_eq!(
            decode_request(Protocol::PingV1, &wrong, 1024),
            Err(ReqRespError::InvalidLength {
                len: 9,
                min: 8,
                max: 8
            })
        );
        // Mutation: one extra byte after the payload.
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            decode_request(Protocol::PingV1, &trailing, 1024),
            Err(ReqRespError::TrailingBytes)
        );
        // Mutation: the stream closes one byte early.
        assert_eq!(
            decode_request(Protocol::PingV1, &wire[..wire.len() - 1], 1024),
            Err(ReqRespError::UnexpectedEof)
        );
        // Mutation: the frames do not open with the identifier.
        let mut no_ident = wire;
        no_ident[1] = 0x00;
        assert_eq!(
            decode_request(Protocol::PingV1, &no_ident, 1024),
            Err(ReqRespError::MissingStreamIdentifier)
        );
    }

    #[test]
    fn response_chunks_with_context_and_error() {
        let digest = ForkDigest([1, 2, 3, 4]);
        let block = vec![5u8; 300];
        let mut wire = Vec::new();
        encode_response_chunk(
            &ResponseChunk::success(Some(digest), block.clone()),
            &mut wire,
        );
        // Success chunk: [0x00][01 02 03 04][varint 300 = ac 02]...
        assert_eq!(&wire[..7], &[0x00, 1, 2, 3, 4, 0xac, 0x02]);
        encode_response_chunk(
            &ResponseChunk::error(ResponseCode::ResourceUnavailable, "pruned"),
            &mut wire,
        );

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
        encode_response_chunk(
            &ResponseChunk::success(Some(ForkDigest::ZERO), payload.clone()),
            &mut wire,
        );
        let mut decoder = ResponseDecoder::new(Protocol::BeaconBlocksByRootV2, 10_485_760);
        decoder.feed(&wire);
        assert_eq!(decoder.next_chunk().unwrap().unwrap().payload, payload);
    }

    #[test]
    fn response_bound_is_checked_from_the_header() {
        // A status response claiming 1000 bytes fails before any payload arrives.
        let mut decoder = ResponseDecoder::new(Protocol::StatusV2, 10_485_760);
        decoder.feed(&[0x00, 0xe8, 0x07]);
        assert_eq!(
            decoder.next_chunk(),
            Err(ReqRespError::InvalidLength {
                len: 1000,
                min: 92,
                max: 92
            })
        );
    }

    #[test]
    fn partial_chunk_at_eof() {
        let mut decoder = ResponseDecoder::new(Protocol::PingV1, 1024);
        decoder.feed(&[0x00, 0x08]);
        assert_eq!(decoder.next_chunk(), Ok(None));
        assert_eq!(decoder.finish(), Err(ReqRespError::UnexpectedEof));
    }

    #[test]
    fn response_codes() {
        for byte in 0..=255u8 {
            assert_eq!(ResponseCode::from_byte(byte).to_byte(), byte);
        }
        assert_eq!(ResponseCode::from_byte(4), ResponseCode::Reserved(4));
        assert_eq!(
            ResponseCode::from_byte(128),
            ResponseCode::ClientSpecific(128)
        );
    }

    proptest! {
        #[test]
        fn chunk_round_trip(payload in proptest::collection::vec(any::<u8>(), 100..3000), digest: [u8; 4], cut in 1usize..64) {
            let chunk = ResponseChunk::success(Some(ForkDigest(digest)), payload);
            let mut wire = Vec::new();
            encode_response_chunk(&chunk, &mut wire);
            encode_response_chunk(&chunk, &mut wire);
            let mut decoder = ResponseDecoder::new(Protocol::BeaconBlocksByRangeV2, 10_485_760);
            let mut decoded = Vec::new();
            for piece in wire.chunks(cut) {
                decoder.feed(piece);
                while let Some(chunk) = decoder.next_chunk().unwrap() {
                    decoded.push(chunk);
                }
            }
            prop_assert_eq!(decoded, vec![chunk.clone(), chunk]);
        }

        #[test]
        fn request_round_trip(roots in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let wire = encode_request(Protocol::BeaconBlocksByRootV2, &roots);
            prop_assert_eq!(decode_request(Protocol::BeaconBlocksByRootV2, &wire, 10_485_760), Ok(roots));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            for protocol in Protocol::ALL {
                let _ = decode_request(protocol, &bytes, 10_485_760);
                let mut decoder = ResponseDecoder::new(protocol, 10_485_760);
                decoder.feed(&bytes);
                while let Ok(Some(_)) = decoder.next_chunk() {}
            }
        }
    }
}
