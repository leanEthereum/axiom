//! Frames: the units of meaning inside a packet payload, per RFC 9000, section 19.
//!
//! # Overview
//!
//! A payload is a sequence of frames, each led by a varint type.
//! The packet type limits which frames may appear, per RFC 9000, section 12.4:
//!
//! - Initial and Handshake packets carry only PADDING, PING, ACK, CRYPTO, and transport closes.
//! - 1-RTT packets carry every frame.
//!
//! Decoding borrows data from the payload, so CRYPTO and STREAM data is never copied twice.

mod ack;

pub(crate) use ack::AckFrame;

use super::{ConnectionId, DecodeError, StreamId, VarInt, reader::Reader};

/// The frame type values of version 1.
mod types {
    pub(super) const PADDING: u64 = 0x00;
    pub(super) const PING: u64 = 0x01;
    pub(super) const RESET_STREAM: u64 = 0x04;
    pub(super) const STOP_SENDING: u64 = 0x05;
    pub(super) const CRYPTO: u64 = 0x06;
    pub(super) const NEW_TOKEN: u64 = 0x07;
    pub(super) const STREAM: u64 = 0x08;
    pub(super) const STREAM_LAST: u64 = 0x0f;
    pub(super) const MAX_DATA: u64 = 0x10;
    pub(super) const MAX_STREAM_DATA: u64 = 0x11;
    pub(super) const MAX_STREAMS_BIDI: u64 = 0x12;
    pub(super) const MAX_STREAMS_UNI: u64 = 0x13;
    pub(super) const DATA_BLOCKED: u64 = 0x14;
    pub(super) const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub(super) const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub(super) const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub(super) const NEW_CONNECTION_ID: u64 = 0x18;
    pub(super) const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub(super) const PATH_CHALLENGE: u64 = 0x1a;
    pub(super) const PATH_RESPONSE: u64 = 0x1b;
    pub(super) const CONNECTION_CLOSE: u64 = 0x1c;
    pub(super) const APPLICATION_CLOSE: u64 = 0x1d;
    pub(super) const HANDSHAKE_DONE: u64 = 0x1e;
}

/// STREAM type bit: an offset field is present.
const STREAM_OFF: u64 = 0x04;

/// STREAM type bit: a length field is present.
const STREAM_LEN: u64 = 0x02;

/// STREAM type bit: this frame ends the stream.
const STREAM_FIN: u64 = 0x01;

/// The largest stream count a MAX_STREAMS or STREAMS_BLOCKED frame may state: 2^60.
///
/// A larger count would need stream ids beyond the 62-bit varint range.
const MAX_STREAM_COUNT: u64 = 1 << 60;

/// Bytes of a stateless reset token.
pub(crate) const RESET_TOKEN_LEN: usize = 16;

/// Which kind of packet carries a payload, for the frame rules of RFC 9000, table 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketKind {
    /// Initial or Handshake.
    Handshake,
    /// 1-RTT.
    Application,
}

/// One frame, borrowing its data from the payload it was decoded from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Frame<'a> {
    /// A run of PADDING bytes.
    Padding(usize),
    /// A PING.
    Ping,
    /// An ACK.
    Ack(AckFrame),
    /// RESET_STREAM: the sender abandons a stream.
    ResetStream {
        /// The stream.
        id: StreamId,
        /// The application error code.
        error_code: u64,
        /// The stream's final size.
        final_size: u64,
    },
    /// STOP_SENDING: the receiver no longer wants a stream's data.
    StopSending {
        /// The stream.
        id: StreamId,
        /// The application error code.
        error_code: u64,
    },
    /// CRYPTO: TLS handshake bytes at an offset.
    Crypto {
        /// The offset in the level's crypto stream.
        offset: u64,
        /// The bytes.
        data: &'a [u8],
    },
    /// NEW_TOKEN: a token for future connections.
    NewToken(&'a [u8]),
    /// STREAM: application bytes at an offset.
    Stream {
        /// The stream.
        id: StreamId,
        /// The offset of the first byte.
        offset: u64,
        /// The bytes.
        data: &'a [u8],
        /// Whether the bytes end the stream.
        fin: bool,
    },
    /// MAX_DATA: the connection-wide receive limit.
    MaxData(u64),
    /// MAX_STREAM_DATA: one stream's receive limit.
    MaxStreamData {
        /// The stream.
        id: StreamId,
        /// The new limit.
        max: u64,
    },
    /// MAX_STREAMS: how many streams of a direction the peer may open.
    MaxStreams {
        /// Bidirectional, else unidirectional.
        bidi: bool,
        /// The cumulative count.
        max: u64,
    },
    /// DATA_BLOCKED: the sender is blocked by the connection limit.
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED: the sender is blocked by a stream limit.
    StreamDataBlocked {
        /// The stream.
        id: StreamId,
        /// The limit it hit.
        limit: u64,
    },
    /// STREAMS_BLOCKED: the sender wants more streams.
    StreamsBlocked {
        /// Bidirectional, else unidirectional.
        bidi: bool,
        /// The limit it hit.
        limit: u64,
    },
    /// NEW_CONNECTION_ID: an extra id the peer may address this endpoint with.
    NewConnectionId {
        /// The sequence number.
        sequence: u64,
        /// Ids below this sequence must be retired.
        retire_prior_to: u64,
        /// The id.
        id: ConnectionId,
        /// The stateless reset token tied to the id.
        reset_token: [u8; RESET_TOKEN_LEN],
    },
    /// RETIRE_CONNECTION_ID: the sender stops using an id.
    RetireConnectionId(u64),
    /// PATH_CHALLENGE: data the peer must echo.
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE: the echo.
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE.
    Close {
        /// The error code.
        error_code: u64,
        /// The triggering frame type for transport closes; none for application closes.
        frame_type: Option<u64>,
        /// The reason phrase.
        reason: &'a [u8],
    },
    /// HANDSHAKE_DONE: the server confirms the handshake.
    HandshakeDone,
}

impl<'a> Frame<'a> {
    /// Decodes one frame from the front of a payload.
    ///
    /// # Errors
    ///
    /// Fails on an unknown type, a truncated frame, or a field out of range.
    pub(crate) fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let frame_type = reader.varint()?.get();
        let malformed = |rule| DecodeError::MalformedFrame { frame_type, rule };
        let frame = match frame_type {
            types::PADDING => {
                // Collapse the whole run: a padded packet holds hundreds of these.
                let run = reader
                    .peek_rest()
                    .iter()
                    .take_while(|byte| **byte == 0)
                    .count();
                reader.bytes(run)?;
                Self::Padding(run + 1)
            }
            types::PING => Self::Ping,
            ack::ACK | ack::ACK_ECN => Self::Ack(AckFrame::decode(reader, frame_type)?),
            types::RESET_STREAM => Self::ResetStream {
                id: StreamId(reader.varint()?.get()),
                error_code: reader.varint()?.get(),
                final_size: reader.varint()?.get(),
            },
            types::STOP_SENDING => Self::StopSending {
                id: StreamId(reader.varint()?.get()),
                error_code: reader.varint()?.get(),
            },
            types::CRYPTO => {
                let offset = reader.varint()?.get();
                let data = reader.length_prefixed()?;
                if offset + data.len() as u64 > VarInt::MAX.get() {
                    return Err(malformed("crypto data ends beyond 2^62 - 1"));
                }
                Self::Crypto { offset, data }
            }
            types::NEW_TOKEN => {
                let token = reader.length_prefixed()?;
                if token.is_empty() {
                    return Err(malformed("empty token"));
                }
                Self::NewToken(token)
            }
            types::STREAM..=types::STREAM_LAST => Self::decode_stream(reader, frame_type)?,
            types::MAX_DATA => Self::MaxData(reader.varint()?.get()),
            types::MAX_STREAM_DATA => Self::MaxStreamData {
                id: StreamId(reader.varint()?.get()),
                max: reader.varint()?.get(),
            },
            types::MAX_STREAMS_BIDI | types::MAX_STREAMS_UNI => Self::MaxStreams {
                bidi: frame_type == types::MAX_STREAMS_BIDI,
                max: Self::stream_count(reader, frame_type)?,
            },
            types::DATA_BLOCKED => Self::DataBlocked(reader.varint()?.get()),
            types::STREAM_DATA_BLOCKED => Self::StreamDataBlocked {
                id: StreamId(reader.varint()?.get()),
                limit: reader.varint()?.get(),
            },
            types::STREAMS_BLOCKED_BIDI | types::STREAMS_BLOCKED_UNI => Self::StreamsBlocked {
                bidi: frame_type == types::STREAMS_BLOCKED_BIDI,
                limit: Self::stream_count(reader, frame_type)?,
            },
            types::NEW_CONNECTION_ID => Self::decode_new_connection_id(reader)?,
            types::RETIRE_CONNECTION_ID => Self::RetireConnectionId(reader.varint()?.get()),
            types::PATH_CHALLENGE => Self::PathChallenge(reader.array()?),
            types::PATH_RESPONSE => Self::PathResponse(reader.array()?),
            types::CONNECTION_CLOSE | types::APPLICATION_CLOSE => {
                let error_code = reader.varint()?.get();
                let frame_type = if frame_type == types::CONNECTION_CLOSE {
                    Some(reader.varint()?.get())
                } else {
                    None
                };
                Self::Close {
                    error_code,
                    frame_type,
                    reason: reader.length_prefixed()?,
                }
            }
            types::HANDSHAKE_DONE => Self::HandshakeDone,
            _ => return Err(DecodeError::UnknownFrame { frame_type }),
        };
        Ok(frame)
    }

    /// Decodes a STREAM frame body, whose type bits say which fields are present.
    fn decode_stream(reader: &mut Reader<'a>, frame_type: u64) -> Result<Self, DecodeError> {
        let id = StreamId(reader.varint()?.get());
        let offset = if frame_type & STREAM_OFF == 0 {
            0
        } else {
            reader.varint()?.get()
        };
        let data = if frame_type & STREAM_LEN == 0 {
            reader.rest()
        } else {
            reader.length_prefixed()?
        };
        if offset + data.len() as u64 > VarInt::MAX.get() {
            return Err(DecodeError::MalformedFrame {
                frame_type,
                rule: "stream data ends beyond 2^62 - 1",
            });
        }
        Ok(Self::Stream {
            id,
            offset,
            data,
            fin: frame_type & STREAM_FIN != 0,
        })
    }

    /// Decodes a NEW_CONNECTION_ID frame body.
    fn decode_new_connection_id(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let malformed = |rule| DecodeError::MalformedFrame {
            frame_type: types::NEW_CONNECTION_ID,
            rule,
        };
        let sequence = reader.varint()?.get();
        let retire_prior_to = reader.varint()?.get();
        if retire_prior_to > sequence {
            return Err(malformed("retire prior to exceeds the sequence number"));
        }
        let len = usize::from(reader.u8()?);
        if !(1..=ConnectionId::MAX_LEN).contains(&len) {
            return Err(malformed("connection id length outside 1 to 20"));
        }
        let id = ConnectionId::new(reader.bytes(len)?)?;
        Ok(Self::NewConnectionId {
            sequence,
            retire_prior_to,
            id,
            reset_token: reader.array()?,
        })
    }

    /// Decodes a stream count, which may not exceed 2^60.
    fn stream_count(reader: &mut Reader<'a>, frame_type: u64) -> Result<u64, DecodeError> {
        let count = reader.varint()?.get();
        if count > MAX_STREAM_COUNT {
            return Err(DecodeError::MalformedFrame {
                frame_type,
                rule: "stream count above 2^60",
            });
        }
        Ok(count)
    }

    /// The type value this frame is written with.
    #[must_use]
    pub(crate) const fn frame_type(&self) -> u64 {
        match self {
            Self::Padding(_) => types::PADDING,
            Self::Ping => types::PING,
            Self::Ack(ack) => {
                if ack.ecn.is_some() {
                    ack::ACK_ECN
                } else {
                    ack::ACK
                }
            }
            Self::ResetStream { .. } => types::RESET_STREAM,
            Self::StopSending { .. } => types::STOP_SENDING,
            Self::Crypto { .. } => types::CRYPTO,
            Self::NewToken(_) => types::NEW_TOKEN,
            Self::Stream { offset, fin, .. } => {
                let mut frame_type = types::STREAM | STREAM_LEN;
                if *offset != 0 {
                    frame_type |= STREAM_OFF;
                }
                if *fin {
                    frame_type |= STREAM_FIN;
                }
                frame_type
            }
            Self::MaxData(_) => types::MAX_DATA,
            Self::MaxStreamData { .. } => types::MAX_STREAM_DATA,
            Self::MaxStreams { bidi: true, .. } => types::MAX_STREAMS_BIDI,
            Self::MaxStreams { bidi: false, .. } => types::MAX_STREAMS_UNI,
            Self::DataBlocked(_) => types::DATA_BLOCKED,
            Self::StreamDataBlocked { .. } => types::STREAM_DATA_BLOCKED,
            Self::StreamsBlocked { bidi: true, .. } => types::STREAMS_BLOCKED_BIDI,
            Self::StreamsBlocked { bidi: false, .. } => types::STREAMS_BLOCKED_UNI,
            Self::NewConnectionId { .. } => types::NEW_CONNECTION_ID,
            Self::RetireConnectionId(_) => types::RETIRE_CONNECTION_ID,
            Self::PathChallenge(_) => types::PATH_CHALLENGE,
            Self::PathResponse(_) => types::PATH_RESPONSE,
            Self::Close {
                frame_type: Some(_),
                ..
            } => types::CONNECTION_CLOSE,
            Self::Close {
                frame_type: None, ..
            } => types::APPLICATION_CLOSE,
            Self::HandshakeDone => types::HANDSHAKE_DONE,
        }
    }

    /// Whether the frame may appear in a packet of a kind, per RFC 9000, table 3.
    #[must_use]
    pub(crate) const fn allowed_in(&self, kind: PacketKind) -> bool {
        match kind {
            PacketKind::Application => true,
            PacketKind::Handshake => matches!(
                self,
                Self::Padding(_)
                    | Self::Ping
                    | Self::Ack(_)
                    | Self::Crypto { .. }
                    | Self::Close {
                        frame_type: Some(_),
                        ..
                    }
            ),
        }
    }

    /// Whether the frame obliges the receiver to acknowledge, per RFC 9002, section 2.
    #[must_use]
    pub(crate) const fn is_ack_eliciting(&self) -> bool {
        !matches!(self, Self::Padding(_) | Self::Ack(_) | Self::Close { .. })
    }

    /// Appends the frame, type included.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        VarInt::saturating(self.frame_type()).encode(out);
        let varint = |value: u64, out: &mut Vec<u8>| VarInt::saturating(value).encode(out);
        match self {
            Self::Padding(run) => out.resize(out.len() + run.saturating_sub(1), 0),
            Self::Ping | Self::HandshakeDone => {}
            Self::Ack(ack) => {
                // The ACK encoder writes its own type byte.
                out.pop();
                ack.encode(out);
            }
            Self::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                varint(id.0, out);
                varint(*error_code, out);
                varint(*final_size, out);
            }
            Self::StopSending { id, error_code } => {
                varint(id.0, out);
                varint(*error_code, out);
            }
            Self::Crypto { offset, data } => {
                varint(*offset, out);
                varint(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Self::NewToken(token) => {
                varint(token.len() as u64, out);
                out.extend_from_slice(token);
            }
            Self::Stream {
                id, offset, data, ..
            } => {
                varint(id.0, out);
                if *offset != 0 {
                    varint(*offset, out);
                }
                varint(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Self::MaxData(value)
            | Self::DataBlocked(value)
            | Self::RetireConnectionId(value)
            | Self::MaxStreams { max: value, .. }
            | Self::StreamsBlocked { limit: value, .. } => varint(*value, out),
            Self::MaxStreamData { id, max: value }
            | Self::StreamDataBlocked { id, limit: value } => {
                varint(id.0, out);
                varint(*value, out);
            }
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            } => {
                varint(*sequence, out);
                varint(*retire_prior_to, out);
                id.encode_with_length(out);
                out.extend_from_slice(reset_token);
            }
            Self::PathChallenge(data) | Self::PathResponse(data) => out.extend_from_slice(data),
            Self::Close {
                error_code,
                frame_type,
                reason,
            } => {
                varint(*error_code, out);
                if let Some(frame_type) = frame_type {
                    varint(*frame_type, out);
                }
                varint(reason.len() as u64, out);
                out.extend_from_slice(reason);
            }
        }
    }

    /// Bytes of the header of a STREAM frame, before its data.
    #[must_use]
    pub(crate) const fn stream_header_len(id: StreamId, offset: u64, data_len: usize) -> usize {
        let offset_len = if offset == 0 {
            0
        } else {
            VarInt::saturating(offset).encoded_len()
        };
        1 + VarInt::saturating(id.0).encoded_len()
            + offset_len
            + VarInt::saturating(data_len as u64).encoded_len()
    }

    /// Bytes of the header of a CRYPTO frame, before its data.
    #[must_use]
    pub(crate) const fn crypto_header_len(offset: u64, data_len: usize) -> usize {
        1 + VarInt::saturating(offset).encoded_len()
            + VarInt::saturating(data_len as u64).encoded_len()
    }
}

/// Walks the frames of a payload.
#[derive(Debug)]
pub(crate) struct FrameIter<'a> {
    /// The bytes not yet decoded.
    reader: Reader<'a>,
}

impl<'a> FrameIter<'a> {
    /// The frames of a decrypted payload.
    #[must_use]
    pub(crate) const fn new(payload: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(payload),
        }
    }
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = Result<Frame<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        let item = Frame::decode(&mut self.reader);
        if item.is_err() {
            // A malformed frame ends the walk: nothing after it can be trusted.
            self.reader.rest();
        }
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// One of each frame, with small but non-trivial fields.
    fn every_frame() -> Vec<Frame<'static>> {
        vec![
            Frame::Padding(3),
            Frame::Ping,
            Frame::Ack(AckFrame {
                ranges: vec![10..12, 4..8],
                delay: 9,
                ecn: None,
            }),
            Frame::ResetStream {
                id: StreamId(4),
                error_code: 7,
                final_size: 300,
            },
            Frame::StopSending {
                id: StreamId(1),
                error_code: 2,
            },
            Frame::Crypto {
                offset: 100,
                data: b"hello",
            },
            Frame::NewToken(b"tok"),
            Frame::Stream {
                id: StreamId(8),
                offset: 0,
                data: b"abc",
                fin: false,
            },
            Frame::Stream {
                id: StreamId(8),
                offset: 70_000,
                data: b"xyz",
                fin: true,
            },
            Frame::MaxData(1 << 20),
            Frame::MaxStreamData {
                id: StreamId(0),
                max: 65_536,
            },
            Frame::MaxStreams {
                bidi: true,
                max: 256,
            },
            Frame::MaxStreams {
                bidi: false,
                max: 0,
            },
            Frame::DataBlocked(5),
            Frame::StreamDataBlocked {
                id: StreamId(5),
                limit: 6,
            },
            Frame::StreamsBlocked {
                bidi: true,
                limit: 100,
            },
            Frame::StreamsBlocked {
                bidi: false,
                limit: 1,
            },
            Frame::NewConnectionId {
                sequence: 2,
                retire_prior_to: 1,
                id: ConnectionId::new(&[9; 8]).unwrap(),
                reset_token: [3; 16],
            },
            Frame::RetireConnectionId(1),
            Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]),
            Frame::PathResponse([8; 8]),
            Frame::Close {
                error_code: 0x0a,
                frame_type: Some(0x08),
                reason: b"bad",
            },
            Frame::Close {
                error_code: 0,
                frame_type: None,
                reason: b"",
            },
            Frame::HandshakeDone,
        ]
    }

    #[test]
    fn every_frame_round_trips() {
        let frames = every_frame();
        let mut payload = Vec::new();
        for frame in &frames {
            frame.encode(&mut payload);
        }
        let decoded: Result<Vec<_>, _> = FrameIter::new(&payload).collect();
        assert_eq!(decoded, Ok(frames));
    }

    #[test]
    fn stream_frame_bits_and_header_length() {
        // Offset present and FIN set: type 0x08 | 0x04 | 0x02 | 0x01.
        let frame = Frame::Stream {
            id: StreamId(8),
            offset: 70_000,
            data: b"xyz",
            fin: true,
        };
        let mut out = Vec::new();
        frame.encode(&mut out);
        assert_eq!(out[0], 0x0f);
        // One type byte, one id byte, a four-byte offset, a one-byte length.
        assert_eq!(Frame::stream_header_len(StreamId(8), 70_000, 3), 7);
        assert_eq!(out.len(), 7 + 3);

        // A STREAM frame without the length bit runs to the end of the payload.
        let payload = [0x08, 0x04, b'r', b'e', b's', b't'];
        assert_eq!(
            FrameIter::new(&payload).next(),
            Some(Ok(Frame::Stream {
                id: StreamId(4),
                offset: 0,
                data: b"rest",
                fin: false,
            }))
        );
        assert_eq!(Frame::crypto_header_len(0, 200), 4);
    }

    #[test]
    fn packet_kind_rules() {
        // Handshake-level packets refuse stream frames and application closes.
        let stream = Frame::Stream {
            id: StreamId(0),
            offset: 0,
            data: b"",
            fin: false,
        };
        assert!(!stream.allowed_in(PacketKind::Handshake));
        assert!(stream.allowed_in(PacketKind::Application));
        let app_close = Frame::Close {
            error_code: 0,
            frame_type: None,
            reason: b"",
        };
        assert!(!app_close.allowed_in(PacketKind::Handshake));
        assert!(Frame::Ping.allowed_in(PacketKind::Handshake));
        assert!(!Frame::HandshakeDone.allowed_in(PacketKind::Handshake));

        // ACK, PADDING and CONNECTION_CLOSE do not elicit acknowledgments.
        assert!(!Frame::Padding(1).is_ack_eliciting());
        assert!(!app_close.is_ack_eliciting());
        assert!(Frame::Ping.is_ack_eliciting());
    }

    #[test]
    fn refuses_malformed_frames() {
        fn decode(bytes: &[u8]) -> Option<Result<Frame<'_>, DecodeError>> {
            FrameIter::new(bytes).next()
        }
        assert_eq!(
            decode(&[0x21]),
            Some(Err(DecodeError::UnknownFrame { frame_type: 0x21 }))
        );
        assert_eq!(
            decode(&[0x07, 0x00]),
            Some(Err(DecodeError::MalformedFrame {
                frame_type: 0x07,
                rule: "empty token"
            }))
        );
        // NEW_CONNECTION_ID with retire prior to 3 above sequence 2.
        assert_eq!(
            decode(&[0x18, 0x02, 0x03, 0x01, 0xaa]),
            Some(Err(DecodeError::MalformedFrame {
                frame_type: 0x18,
                rule: "retire prior to exceeds the sequence number"
            }))
        );
        // NEW_CONNECTION_ID with a zero-length id.
        assert_eq!(
            decode(&[0x18, 0x02, 0x00, 0x00]),
            Some(Err(DecodeError::MalformedFrame {
                frame_type: 0x18,
                rule: "connection id length outside 1 to 20"
            }))
        );
        // MAX_STREAMS of 2^60 + 1.
        let mut bytes = vec![0x12];
        VarInt::new((1 << 60) + 1).unwrap().encode(&mut bytes);
        assert_eq!(
            decode(&bytes),
            Some(Err(DecodeError::MalformedFrame {
                frame_type: 0x12,
                rule: "stream count above 2^60"
            }))
        );
        // A STREAM frame whose end passes 2^62 - 1.
        let mut bytes = vec![0x0e, 0x00];
        VarInt::MAX.encode(&mut bytes);
        bytes.extend_from_slice(&[0x01, 0xff]);
        assert_eq!(
            decode(&bytes),
            Some(Err(DecodeError::MalformedFrame {
                frame_type: 0x0e,
                rule: "stream data ends beyond 2^62 - 1"
            }))
        );
    }

    #[test]
    fn a_malformed_frame_ends_the_walk() {
        // A PING, then a truncated MAX_DATA, then a PING that is never reached.
        let payload = [0x01, 0x10, 0x80, 0x01];
        let frames: Vec<_> = FrameIter::new(&payload).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], Ok(Frame::Ping));
        assert!(frames[1].is_err());
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            for frame in FrameIter::new(&bytes).flatten() {
                let mut out = Vec::new();
                frame.encode(&mut out);
            }
        }

        #[test]
        fn stream_frames_round_trip(
            id in 0_u64..1 << 40,
            offset in 0_u64..1 << 40,
            data in proptest::collection::vec(any::<u8>(), 0..64),
            fin in any::<bool>(),
        ) {
            let frame = Frame::Stream { id: StreamId(id), offset, data: &data, fin };
            let mut out = Vec::new();
            frame.encode(&mut out);
            prop_assert_eq!(out.len(), Frame::stream_header_len(StreamId(id), offset, data.len()) + data.len());
            let decoded = FrameIter::new(&out).next();
            prop_assert_eq!(decoded, Some(Ok(frame)));
        }
    }
}
