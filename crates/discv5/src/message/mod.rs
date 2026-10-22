//! The protocol messages carried inside sealed packets.
//!
//! See discv5-wire.md, "Protocol Messages".

mod error;
mod request_id;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axiom_rlp::{Decoder, Encoder};
pub use error::MessageError;
pub use request_id::RequestId;

use crate::{distance::LogDistance, enr::Enr};

/// Type byte of PING.
const PING: u8 = 0x01;

/// Type byte of PONG.
const PONG: u8 = 0x02;

/// Type byte of FINDNODE.
const FIND_NODE: u8 = 0x03;

/// Type byte of NODES.
const NODES: u8 = 0x04;

/// Type byte of TALKREQ.
const TALK_REQ: u8 = 0x05;

/// Type byte of TALKRESP.
const TALK_RESP: u8 = 0x06;

/// One discv5 message: a type byte, then an RLP list whose first item is the request id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Checks liveness and announces the sender's record version.
    Ping {
        /// The request id.
        request_id: RequestId,
        /// The sender's record sequence number.
        enr_seq: u64,
    },

    /// Answers PING, mirroring the address the request came from.
    Pong {
        /// The request id of the PING.
        request_id: RequestId,
        /// The sender's record sequence number.
        enr_seq: u64,
        /// The address the PING arrived from.
        recipient_ip: IpAddr,
        /// The port the PING arrived from.
        recipient_port: u16,
    },

    /// Asks for nodes at given logarithmic distances from the recipient.
    FindNode {
        /// The request id.
        request_id: RequestId,
        /// The distances, zero naming the recipient's own record.
        distances: Vec<LogDistance>,
    },

    /// Answers FINDNODE with records, in one or more messages.
    Nodes {
        /// The request id of the FINDNODE.
        request_id: RequestId,
        /// How many NODES messages answer the request.
        total: u64,
        /// The records in this message.
        ///
        /// Records that fail verification are dropped at decoding.
        enrs: Vec<Enr>,
    },

    /// An application request under a named protocol.
    TalkReq {
        /// The request id.
        request_id: RequestId,
        /// The application protocol name.
        protocol: Vec<u8>,
        /// The request payload.
        request: Vec<u8>,
    },

    /// Answers TALKREQ, empty when the protocol is unknown.
    TalkResp {
        /// The request id of the TALKREQ.
        request_id: RequestId,
        /// The response payload.
        response: Vec<u8>,
    },
}

impl Message {
    /// The request id.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::Ping { request_id, .. }
            | Self::Pong { request_id, .. }
            | Self::FindNode { request_id, .. }
            | Self::Nodes { request_id, .. }
            | Self::TalkReq { request_id, .. }
            | Self::TalkResp { request_id, .. } => *request_id,
        }
    }

    /// Whether the message is a request, as opposed to a response.
    #[must_use]
    pub const fn is_request(&self) -> bool {
        matches!(
            self,
            Self::Ping { .. } | Self::FindNode { .. } | Self::TalkReq { .. }
        )
    }

    /// The plaintext: type byte, then the RLP body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        let kind = match self {
            Self::Ping {
                request_id,
                enr_seq,
            } => {
                encoder.list(|list| {
                    list.bytes(request_id.as_bytes()).uint(*enr_seq);
                });
                PING
            }
            Self::Pong {
                request_id,
                enr_seq,
                recipient_ip,
                recipient_port,
            } => {
                // The address is its raw 4 or 16 octets.
                let ip = match recipient_ip {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                };
                encoder.list(|list| {
                    list.bytes(request_id.as_bytes())
                        .uint(*enr_seq)
                        .bytes(&ip)
                        .uint(u64::from(*recipient_port));
                });
                PONG
            }
            Self::FindNode {
                request_id,
                distances,
            } => {
                encoder.list(|list| {
                    list.bytes(request_id.as_bytes()).list(|inner| {
                        for distance in distances {
                            inner.uint(u64::from(distance.get()));
                        }
                    });
                });
                FIND_NODE
            }
            Self::Nodes {
                request_id,
                total,
                enrs,
            } => {
                encoder.list(|list| {
                    list.bytes(request_id.as_bytes())
                        .uint(*total)
                        .list(|inner| {
                            for enr in enrs {
                                inner.raw(enr.as_bytes());
                            }
                        });
                });
                NODES
            }
            Self::TalkReq {
                request_id,
                protocol,
                request,
            } => {
                encoder.list(|list| {
                    list.bytes(request_id.as_bytes())
                        .bytes(protocol)
                        .bytes(request);
                });
                TALK_REQ
            }
            Self::TalkResp {
                request_id,
                response,
            } => {
                encoder.list(|list| {
                    list.bytes(request_id.as_bytes()).bytes(response);
                });
                TALK_RESP
            }
        };
        // The type byte leads the body.
        let mut out = vec![kind];
        out.extend(encoder.finish());
        out
    }

    /// Decodes a plaintext.
    ///
    /// # Errors
    ///
    /// Fails on an unknown type, on non-canonical RLP, on trailing bytes,
    /// and on out-of-range request ids, distances, or addresses.
    pub fn decode(plaintext: &[u8]) -> Result<Self, MessageError> {
        // Phase 1: the type byte, then exactly one list.
        let (&kind, body) = plaintext.split_first().ok_or(MessageError::Empty)?;
        let mut outer = Decoder::new(body);
        let mut list = outer.list()?;
        outer.finish()?;
        let request_id = list.bytes()?;
        let request_id =
            RequestId::new(request_id).ok_or(MessageError::RequestIdTooLong(request_id.len()))?;

        // Phase 2: the fields of the kind.
        let message = match kind {
            PING => Self::Ping {
                request_id,
                enr_seq: list.uint()?,
            },
            PONG => Self::Pong {
                request_id,
                enr_seq: list.uint()?,
                recipient_ip: Self::decode_ip(list.bytes()?)?,
                recipient_port: list.u16()?,
            },
            FIND_NODE => {
                let mut inner = list.list()?;
                let mut distances = Vec::new();
                while !inner.is_empty() {
                    let value = inner.uint()?;
                    let distance = u16::try_from(value)
                        .ok()
                        .and_then(|value| LogDistance::new(value).ok())
                        .ok_or(MessageError::Distance(value))?;
                    distances.push(distance);
                }
                Self::FindNode {
                    request_id,
                    distances,
                }
            }
            NODES => {
                let total = list.uint()?;
                let mut inner = list.list()?;
                let mut enrs = Vec::new();
                while !inner.is_empty() {
                    // A bad record is dropped alone; its neighbours still count.
                    if let Ok(enr) = Enr::decode(inner.raw()?) {
                        enrs.push(enr);
                    }
                }
                Self::Nodes {
                    request_id,
                    total,
                    enrs,
                }
            }
            TALK_REQ => Self::TalkReq {
                request_id,
                protocol: list.bytes()?.to_vec(),
                request: list.bytes()?.to_vec(),
            },
            TALK_RESP => Self::TalkResp {
                request_id,
                response: list.bytes()?.to_vec(),
            },
            other => return Err(MessageError::UnknownType(other)),
        };
        // Phase 3: nothing may follow the last field.
        list.finish()?;
        Ok(message)
    }

    /// An address of 4 or 16 octets.
    fn decode_ip(bytes: &[u8]) -> Result<IpAddr, MessageError> {
        // The length alone tells the family.
        if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
            return Ok(IpAddr::V4(Ipv4Addr::from(octets)));
        }
        if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
            return Ok(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        Err(MessageError::IpLength(bytes.len()))
    }
}

#[cfg(test)]
mod tests {
    use axiom_rlp::RlpError;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn ping_matches_the_wire_vector_plaintext() {
        // The wire vectors' PING: request id 0x00000001, sequence 2.
        let ping = Message::Ping {
            request_id: RequestId::new(&[0, 0, 0, 1]).unwrap(),
            enr_seq: 2,
        };
        assert_eq!(ping.encode(), [0x01, 0xc6, 0x84, 0, 0, 0, 1, 0x02]);
        assert_eq!(Message::decode(&ping.encode()), Ok(ping));
    }

    #[test]
    fn every_kind_round_trips() {
        let request_id = RequestId::from_u64(77);
        let messages = [
            Message::Pong {
                request_id,
                enr_seq: 9,
                recipient_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                recipient_port: 30303,
            },
            Message::Pong {
                request_id,
                enr_seq: 0,
                recipient_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                recipient_port: 1,
            },
            Message::FindNode {
                request_id,
                distances: vec![LogDistance::ZERO, LogDistance::MAX],
            },
            Message::Nodes {
                request_id,
                total: 1,
                enrs: vec![],
            },
            Message::TalkReq {
                request_id,
                protocol: b"eth2".to_vec(),
                request: vec![1, 2, 3],
            },
            Message::TalkResp {
                request_id,
                response: vec![],
            },
        ];
        for message in messages {
            assert_eq!(Message::decode(&message.encode()), Ok(message));
        }
    }

    #[test]
    fn decoding_is_strict() {
        // Empty plaintext.
        assert_eq!(Message::decode(&[]), Err(MessageError::Empty));
        // Type 0x07 (REGTOPIC) is not supported.
        assert_eq!(
            Message::decode(&[0x07, 0xc1, 0x80]),
            Err(MessageError::UnknownType(0x07))
        );
        // A 9-byte request id.
        let mut body = vec![0x01, 0xcb, 0x89];
        body.extend_from_slice(&[1; 9]);
        body.push(0x01);
        assert_eq!(
            Message::decode(&body),
            Err(MessageError::RequestIdTooLong(9))
        );
        // Distance 257 is outside the keyspace.
        assert_eq!(
            Message::decode(&[0x03, 0xc5, 0x80, 0xc3, 0x82, 0x01, 0x01]),
            Err(MessageError::Distance(257))
        );
        // An extra field after a PING's sequence number.
        assert_eq!(
            Message::decode(&[0x01, 0xc3, 0x80, 0x01, 0x02]),
            Err(MessageError::Rlp(RlpError::TrailingBytes { remaining: 1 }))
        );
        // A 5-byte address in a PONG.
        assert_eq!(
            Message::decode(&[0x02, 0xc9, 0x80, 0x01, 0x85, 1, 2, 3, 4, 5, 0x01]),
            Err(MessageError::IpLength(5))
        );
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
            // Arbitrary plaintexts yield a message or an error.
            let _ = Message::decode(&bytes);
        }

        #[test]
        fn talk_round_trips(
            id in prop::collection::vec(any::<u8>(), 0..=8),
            protocol in prop::collection::vec(any::<u8>(), 0..20),
            request in prop::collection::vec(any::<u8>(), 0..100),
        ) {
            // Any request id up to 8 bytes and any payload survive a round trip.
            let message = Message::TalkReq {
                request_id: RequestId::new(&id).unwrap(),
                protocol,
                request,
            };
            prop_assert_eq!(Message::decode(&message.encode()), Ok(message));
        }
    }
}
