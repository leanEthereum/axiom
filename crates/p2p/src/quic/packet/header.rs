//! Packet headers as received, before header protection is removed.
//!
//! # Overview
//!
//! A datagram carries one or more packets.
//! Long-header packets state their length, so several may share a datagram.
//! A short-header packet runs to the end of the datagram, so it comes last.
//!
//! The first byte and the packet number are masked by header protection.
//! Everything before the packet number is readable as is, which is what this module parses.
//!
//! ```text
//! long:  1 1 TT RR PP | version (4) | dcid len, dcid | scid len, scid | type-specific
//! short: 0 1 S RR K PP | dcid | packet number (1-4) | payload
//! ```
//!
//! See RFC 9000, section 17, and RFC 8999 for the version-independent fields.

use super::super::{ConnectionId, DecodeError, VERSION, reader::Reader};

/// The header form bit: set for long headers.
pub(crate) const LONG_FORM: u8 = 0x80;

/// The fixed bit, set in every version 1 packet.
pub(crate) const FIXED_BIT: u8 = 0x40;

/// Bytes of a Retry integrity tag.
pub(crate) const RETRY_TAG_LEN: usize = 16;

/// The type of a long-header packet, per RFC 9000, section 17.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LongType {
    /// The first flights of the handshake, under keys any observer can derive.
    Initial,
    /// Early data, which this stack never sends and drops on receipt.
    ZeroRtt,
    /// The rest of the handshake.
    Handshake,
    /// A server's request to prove the client address.
    Retry,
}

impl LongType {
    /// The two type bits in the first byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::ZeroRtt => 1,
            Self::Handshake => 2,
            Self::Retry => 3,
        }
    }

    /// The type of a first byte.
    #[must_use]
    pub const fn from_first_byte(first: u8) -> Self {
        match (first >> 4) & 0x03 {
            0 => Self::Initial,
            1 => Self::ZeroRtt,
            2 => Self::Handshake,
            _ => Self::Retry,
        }
    }
}

/// The readable part of a received packet's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Header<'a> {
    /// A version 1 long-header packet with a protected packet number.
    Long {
        /// Initial, 0-RTT, or Handshake.
        kind: LongType,
        /// The destination connection id.
        dcid: ConnectionId,
        /// The source connection id.
        scid: ConnectionId,
        /// The address validation token, carried by Initial packets only.
        token: &'a [u8],
    },
    /// A Retry packet.
    Retry {
        /// The destination connection id.
        dcid: ConnectionId,
        /// The server's new connection id.
        scid: ConnectionId,
        /// The token the client must echo.
        token: &'a [u8],
        /// The integrity tag over the pseudo-packet.
        tag: [u8; RETRY_TAG_LEN],
    },
    /// A short-header packet.
    Short {
        /// The destination connection id.
        dcid: ConnectionId,
    },
    /// A Version Negotiation packet.
    VersionNegotiation {
        /// The destination connection id.
        dcid: ConnectionId,
        /// The source connection id.
        scid: ConnectionId,
        /// The versions the server supports.
        versions: Vec<u32>,
    },
    /// A long header of a version this stack does not speak.
    UnsupportedVersion {
        /// The version.
        version: u32,
        /// The destination connection id.
        dcid: ConnectionId,
        /// The source connection id.
        scid: ConnectionId,
    },
}

/// One packet cut out of a datagram, its header parsed, its protection still on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedPacket<'a> {
    /// The parsed header.
    pub header: Header<'a>,
    /// The whole packet: header, packet number, and sealed payload.
    pub bytes: &'a [u8],
    /// Where the packet number starts, for protected packets.
    pub pn_offset: usize,
}

impl<'a> ProtectedPacket<'a> {
    /// Cuts the first packet off a datagram.
    ///
    /// # Arguments
    ///
    /// - `datagram`: the remaining bytes of the datagram.
    /// - `local_cid_len`: the length of this endpoint's connection ids, which short headers omit.
    ///
    /// # Returns
    ///
    /// The packet, and the bytes of the datagram after it.
    ///
    /// # Errors
    ///
    /// Fails on a header that does not parse.
    pub fn parse(
        datagram: &'a [u8],
        local_cid_len: usize,
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        let mut reader = Reader::new(datagram);
        let first = reader.u8()?;
        if first & LONG_FORM == 0 {
            return Self::parse_short(datagram, reader, first, local_cid_len);
        }
        // The version-independent fields of RFC 8999, section 5.1.
        let version = reader.u32()?;
        let dcid = Self::connection_id(&mut reader)?;
        let scid = Self::connection_id(&mut reader)?;
        if version == 0 {
            return Self::parse_version_negotiation(datagram, reader, dcid, scid);
        }
        if version != VERSION {
            let header = Header::UnsupportedVersion {
                version,
                dcid,
                scid,
            };
            let packet = Self {
                header,
                bytes: datagram,
                pn_offset: 0,
            };
            return Ok((packet, &[]));
        }
        if first & FIXED_BIT == 0 {
            return Err(DecodeError::MalformedHeader {
                rule: "fixed bit is zero",
            });
        }
        let kind = LongType::from_first_byte(first);
        if kind == LongType::Retry {
            return Self::parse_retry(datagram, reader, dcid, scid);
        }
        let token = if kind == LongType::Initial {
            reader.length_prefixed()?
        } else {
            &[]
        };
        // The length covers the packet number and the payload.
        let length = reader.length()?;
        let pn_offset = datagram.len() - reader.remaining();
        let end = pn_offset + length;
        // The smallest packet holds a one-byte number and a four-byte sample after it, plus a tag.
        // RFC 9001, section 5.4.2, guarantees senders pad to that.
        if length < 4 + RETRY_TAG_LEN {
            return Err(DecodeError::MalformedHeader {
                rule: "packet too short to sample for header protection",
            });
        }
        let packet = Self {
            header: Header::Long {
                kind,
                dcid,
                scid,
                token,
            },
            bytes: &datagram[..end],
            pn_offset,
        };
        Ok((packet, &datagram[end..]))
    }

    /// The type-specific part of a short header: everything runs to the datagram end.
    fn parse_short(
        datagram: &'a [u8],
        mut reader: Reader<'a>,
        first: u8,
        local_cid_len: usize,
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        if first & FIXED_BIT == 0 {
            return Err(DecodeError::MalformedHeader {
                rule: "fixed bit is zero",
            });
        }
        let dcid = ConnectionId::new(reader.bytes(local_cid_len)?)?;
        let pn_offset = 1 + local_cid_len;
        if reader.remaining() < 4 + RETRY_TAG_LEN {
            return Err(DecodeError::MalformedHeader {
                rule: "packet too short to sample for header protection",
            });
        }
        let packet = Self {
            header: Header::Short { dcid },
            bytes: datagram,
            pn_offset,
        };
        Ok((packet, &[]))
    }

    /// A Version Negotiation packet: a list of 32-bit versions to the end.
    fn parse_version_negotiation(
        datagram: &'a [u8],
        mut reader: Reader<'a>,
        dcid: ConnectionId,
        scid: ConnectionId,
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        let list = reader.rest();
        if list.is_empty() || list.len() % 4 != 0 {
            return Err(DecodeError::MalformedHeader {
                rule: "version list is empty or not a multiple of four bytes",
            });
        }
        let versions = list
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        let packet = Self {
            header: Header::VersionNegotiation {
                dcid,
                scid,
                versions,
            },
            bytes: datagram,
            pn_offset: 0,
        };
        Ok((packet, &[]))
    }

    /// A Retry packet: a token, then the integrity tag, to the end.
    fn parse_retry(
        datagram: &'a [u8],
        mut reader: Reader<'a>,
        dcid: ConnectionId,
        scid: ConnectionId,
    ) -> Result<(Self, &'a [u8]), DecodeError> {
        let rest = reader.rest();
        let Some(token_len) = rest.len().checked_sub(RETRY_TAG_LEN) else {
            return Err(DecodeError::Truncated {
                needed: RETRY_TAG_LEN,
                available: rest.len(),
            });
        };
        let (token, tag) = rest.split_at(token_len);
        let mut tag_bytes = [0; RETRY_TAG_LEN];
        tag_bytes.copy_from_slice(tag);
        let packet = Self {
            header: Header::Retry {
                dcid,
                scid,
                token,
                tag: tag_bytes,
            },
            bytes: datagram,
            pn_offset: 0,
        };
        Ok((packet, &[]))
    }

    /// A length-prefixed connection id of a long header.
    fn connection_id(reader: &mut Reader<'_>) -> Result<ConnectionId, DecodeError> {
        let len = usize::from(reader.u8()?);
        // Versions other than 1 may use up to 255 bytes; such packets are dropped here.
        if len > ConnectionId::MAX_LEN {
            return Err(DecodeError::ConnectionIdTooLong { len });
        }
        ConnectionId::new(reader.bytes(len)?)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn cid(bytes: &[u8]) -> ConnectionId {
        ConnectionId::new(bytes).unwrap()
    }

    #[test]
    fn parses_the_rfc_9001_client_initial_header() {
        // RFC 9001, appendix A.2: protected first byte 0xc0, dcid 8394c8f03e515708, no scid.
        // No token, length 1182, then the masked packet number.
        let mut datagram = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e,
        ];
        datagram.resize(18 + 1182, 0);
        let (packet, rest) = ProtectedPacket::parse(&datagram, 8).unwrap();
        assert_eq!(
            packet.header,
            Header::Long {
                kind: LongType::Initial,
                dcid: cid(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]),
                scid: ConnectionId::EMPTY,
                token: &[],
            }
        );
        assert_eq!(packet.pn_offset, 18);
        assert_eq!(packet.bytes.len(), 1200);
        assert!(rest.is_empty());
    }

    #[test]
    fn splits_coalesced_packets() {
        // Two Handshake packets of 24 payload bytes each, then a short packet.
        let mut datagram = Vec::new();
        for _ in 0..2 {
            datagram.extend_from_slice(&[0xe0, 0, 0, 0, 1, 1, 0xaa, 1, 0xbb, 24]);
            datagram.extend_from_slice(&[0; 24]);
        }
        datagram.push(0x40);
        datagram.extend_from_slice(&[0xaa; 8]);
        datagram.extend_from_slice(&[0; 20]);

        let (first, rest) = ProtectedPacket::parse(&datagram, 8).unwrap();
        assert_eq!(first.bytes.len(), 34);
        let (second, rest) = ProtectedPacket::parse(rest, 8).unwrap();
        assert_eq!(second.pn_offset, 10);
        let (third, rest) = ProtectedPacket::parse(rest, 8).unwrap();
        assert_eq!(
            third.header,
            Header::Short {
                dcid: cid(&[0xaa; 8])
            }
        );
        assert_eq!(third.pn_offset, 9);
        assert!(rest.is_empty());
    }

    #[test]
    fn version_negotiation_and_unknown_versions() {
        // Version 0 lists versions; one of them is v1.
        let datagram = [0x80, 0, 0, 0, 0, 0, 1, 0x11, 0, 0, 0, 1, 0xff, 0, 0, 0x1d];
        let (packet, _) = ProtectedPacket::parse(&datagram, 8).unwrap();
        assert_eq!(
            packet.header,
            Header::VersionNegotiation {
                dcid: ConnectionId::EMPTY,
                scid: cid(&[0x11]),
                versions: vec![1, 0xff00_001d],
            }
        );

        // Version 0xff00001d is draft 29, which this stack does not speak.
        let datagram = [0xc0, 0xff, 0, 0, 0x1d, 1, 0x22, 0];
        let (packet, _) = ProtectedPacket::parse(&datagram, 8).unwrap();
        assert_eq!(
            packet.header,
            Header::UnsupportedVersion {
                version: 0xff00_001d,
                dcid: cid(&[0x22]),
                scid: ConnectionId::EMPTY,
            }
        );
    }

    #[test]
    fn refuses_malformed_headers() {
        // A short header without the fixed bit.
        let datagram = [0x00; 40];
        assert_eq!(
            ProtectedPacket::parse(&datagram, 8),
            Err(DecodeError::MalformedHeader {
                rule: "fixed bit is zero"
            })
        );
        // A Handshake packet whose length runs past the datagram.
        let datagram = [0xe0, 0, 0, 0, 1, 0, 0, 0x40, 0x30, 0, 0];
        assert_eq!(
            ProtectedPacket::parse(&datagram, 8),
            Err(DecodeError::Truncated {
                needed: 48,
                available: 2
            })
        );
        // A 21-byte connection id.
        let datagram = [0xc0, 0, 0, 0, 1, 21];
        assert_eq!(
            ProtectedPacket::parse(&datagram, 8),
            Err(DecodeError::ConnectionIdTooLong { len: 21 })
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let mut rest = bytes.as_slice();
            while let Ok((_, next)) = ProtectedPacket::parse(rest, 8) {
                if next.is_empty() {
                    break;
                }
                rest = next;
            }
        }
    }
}
