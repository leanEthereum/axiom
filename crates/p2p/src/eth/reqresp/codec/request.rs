//! Decoding a request as it arrives, until the requester half-closes.

use std::mem;

use super::payload::PayloadDecoder;
use crate::eth::{
    max_compressed_len,
    reqresp::{Protocol, ReqRespError},
};

/// Longest varint length prefix.
const MAX_PREFIX_LEN: usize = 10;

/// Bytes of the snappy stream identifier.
const STREAM_IDENTIFIER_LEN: usize = 10;

/// What the bytes received so far amount to.
#[derive(Clone, Debug)]
enum Progress {
    /// The payload is still arriving.
    Reading,
    /// The payload is complete and nothing followed it.
    Complete(Vec<u8>),
    /// Bytes followed a complete payload.
    Trailing {
        /// Bytes the payload took on the wire.
        payload_len: usize,
    },
    /// The bytes broke the encoding.
    Failed(ReqRespError),
}

/// Decodes one request from a stream, as bytes arrive.
///
/// The request is final only at end of stream, which is when its outcome is reported.
#[derive(Clone, Debug)]
pub struct RequestDecoder {
    /// The method.
    protocol: Protocol,
    /// The payload decoder, bounded by the method's request type.
    payload: PayloadDecoder,
    /// Bytes received but not yet consumed by the payload decoder.
    buffer: Vec<u8>,
    /// Bytes received in all.
    received: usize,
    /// What the bytes so far amount to.
    progress: Progress,
}

impl RequestDecoder {
    /// A decoder for a request of one method.
    #[must_use]
    pub fn new(protocol: Protocol, max_payload_size: u64) -> Self {
        let bounds = protocol.request_bounds();
        let bounds = *bounds.start()..=(*bounds.end()).min(max_payload_size);
        Self {
            protocol,
            payload: PayloadDecoder::new(bounds),
            buffer: Vec::new(),
            received: 0,
            progress: Progress::Reading,
        }
    }

    /// The method of the request.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Feeds bytes read from the stream.
    ///
    /// # Errors
    ///
    /// Fails once the bytes received exceed the largest framed request of the method.
    /// The bytes are still taken in, so the outcome at end of stream stays well defined.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), ReqRespError> {
        self.received += bytes.len();
        self.take_in(bytes);
        // A request can never exceed its framed bound: varint, identifier, compressed body.
        let max = self.max_framed_len();
        if self.received > max {
            return Err(ReqRespError::RequestTooLarge {
                len: self.received,
                max,
            });
        }
        Ok(())
    }

    /// The request payload, once the requester has closed its side.
    ///
    /// # Errors
    ///
    /// Any violation means the responder answers with an invalid-request error.
    pub fn finish(self) -> Result<Vec<u8>, ReqRespError> {
        match self.progress {
            Progress::Complete(payload) => Ok(payload),
            Progress::Trailing { payload_len } => Err(ReqRespError::TrailingBytes {
                len: self.received - payload_len,
            }),
            Progress::Failed(error) => Err(error),
            // Methods without request content expect no bytes at all.
            Progress::Reading if self.protocol.has_empty_request() => Ok(Vec::new()),
            // The stream closed before the declared length arrived.
            Progress::Reading => Err(ReqRespError::UnexpectedEof {
                received: self.received,
            }),
        }
    }

    /// Advances the payload decoder over new bytes.
    fn take_in(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self.progress {
            Progress::Reading => {}
            // Bytes after the declared length must not exist: end of stream was expected.
            // Invariant: the received count already includes the new bytes.
            Progress::Complete(_) => {
                self.progress = Progress::Trailing {
                    payload_len: self.received - bytes.len(),
                };
                return;
            }
            // Nothing after a violation changes the outcome.
            Progress::Trailing { .. } | Progress::Failed(_) => return,
        }
        // Methods without request content send no bytes at all.
        if self.protocol.has_empty_request() {
            self.progress = Progress::Trailing { payload_len: 0 };
            return;
        }
        // With no unit in progress, decode straight from the new bytes, saving a copy.
        let mut buffer = mem::take(&mut self.buffer);
        let stream = if buffer.is_empty() {
            bytes
        } else {
            buffer.extend_from_slice(bytes);
            &buffer[..]
        };
        let mut input = stream;
        let outcome = self.payload.advance(&mut input);
        let rest_len = input.len();
        self.progress = match outcome {
            Ok(Some(_)) if rest_len > 0 => Progress::Trailing {
                payload_len: self.received - rest_len,
            },
            Ok(Some(payload)) => Progress::Complete(payload),
            Ok(None) => {
                // Keep the unit in progress for the next bytes.
                let consumed = stream.len() - rest_len;
                if buffer.is_empty() {
                    buffer.extend_from_slice(&bytes[consumed..]);
                } else {
                    buffer.drain(..consumed);
                }
                self.buffer = buffer;
                Progress::Reading
            }
            Err(error) => Progress::Failed(error),
        };
    }

    /// The largest number of bytes a request of this method can take on the wire.
    const fn max_framed_len(&self) -> usize {
        let max_ssz = *self.protocol.request_bounds().end();
        MAX_PREFIX_LEN + STREAM_IDENTIFIER_LEN + max_compressed_len(max_ssz) as usize
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a whole request delivered in one piece.
    fn decode(
        protocol: Protocol,
        bytes: &[u8],
        max_payload_size: u64,
    ) -> Result<Vec<u8>, ReqRespError> {
        let mut decoder = RequestDecoder::new(protocol, max_payload_size);
        let _ = decoder.feed(bytes);
        decoder.finish()
    }

    #[test]
    fn request_layout() {
        // A Goodbye request: uint64 reason 1, SSZ = 8 bytes little-endian.
        let ssz = 1u64.to_le_bytes();
        let wire = Protocol::GoodbyeV1.encode_request(&ssz);
        // [0x08 length][ff 06 00 00 sNaPpY][chunk]
        assert_eq!(wire[0], 0x08);
        assert_eq!(
            &wire[1..11],
            &[0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y']
        );
        assert_eq!(
            decode(Protocol::GoodbyeV1, &wire, 10_485_760),
            Ok(ssz.to_vec())
        );
    }

    #[test]
    fn metadata_request_is_empty() {
        assert_eq!(Protocol::MetaDataV3.encode_request(&[]), Vec::<u8>::new());
        assert_eq!(decode(Protocol::MetaDataV3, &[], 1024), Ok(vec![]));
        assert_eq!(
            decode(Protocol::MetaDataV3, &[0], 1024),
            Err(ReqRespError::TrailingBytes { len: 1 })
        );
    }

    #[test]
    fn request_violations() {
        let ssz = [7u8; 8];
        let wire = Protocol::PingV1.encode_request(&ssz);
        // Mutation: declare 9 bytes for a type of exactly 8.
        let mut wrong = wire.clone();
        wrong[0] = 9;
        assert_eq!(
            decode(Protocol::PingV1, &wrong, 1024),
            Err(ReqRespError::InvalidLength {
                len: 9,
                min: 8,
                max: 8
            })
        );
        // Mutation: two extra bytes after the payload.
        let mut trailing = wire.clone();
        trailing.extend([0, 0]);
        assert_eq!(
            decode(Protocol::PingV1, &trailing, 1024),
            Err(ReqRespError::TrailingBytes { len: 2 })
        );
        // Mutation: the stream closes one byte early, after 1 + 10 + 4 + 4 + 8 - 1 = 26 bytes.
        assert_eq!(
            decode(Protocol::PingV1, &wire[..wire.len() - 1], 1024),
            Err(ReqRespError::UnexpectedEof { received: 26 })
        );
        // Mutation: the frames open with a compressed chunk, type 0x00.
        let mut no_ident = wire;
        no_ident[1] = 0x00;
        assert_eq!(
            decode(Protocol::PingV1, &no_ident, 1024),
            Err(ReqRespError::MissingStreamIdentifier { chunk_type: 0x00 })
        );
    }

    #[test]
    fn oversized_request_is_flagged_while_arriving() {
        // A ping request is at most 10 + 10 + (32 + 8 + 1) = 61 framed bytes.
        let mut decoder = RequestDecoder::new(Protocol::PingV1, 1024);
        assert_eq!(decoder.feed(&[0; 61]), Ok(()));
        assert_eq!(
            decoder.feed(&[0]),
            Err(ReqRespError::RequestTooLarge { len: 62, max: 61 })
        );
    }

    proptest! {
        #[test]
        fn request_round_trip(roots in proptest::collection::vec(any::<u8>(), 0..4096), cut in 1usize..64) {
            // Any split of the stream decodes to the same request.
            let wire = Protocol::BeaconBlocksByRootV2.encode_request(&roots);
            let mut decoder = RequestDecoder::new(Protocol::BeaconBlocksByRootV2, 10_485_760);
            for piece in wire.chunks(cut) {
                prop_assert_eq!(decoder.feed(piece), Ok(()));
            }
            prop_assert_eq!(decoder.finish(), Ok(roots));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            for protocol in Protocol::ALL {
                let _ = decode(protocol, &bytes, 10_485_760);
            }
        }
    }
}
