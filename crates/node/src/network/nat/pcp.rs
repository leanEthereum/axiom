//! PCP MAP messages, version 2, as RFC 6887 lays them out.
//!
//! Every number is big-endian.
//! Every address takes 16 bytes; an IPv4 address is IPv4-mapped, per section 5.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{CodecError, MappingProtocol, Transport};

/// The PCP version byte.
const VERSION: u8 = 2;

/// The MAP opcode, per RFC 6887 section 19.2.
const OP_MAP: u8 = 1;

/// The R bit, set on responses.
const RESPONSE: u8 = 0x80;

/// The result code of a server that does not speak the version sent, per section 7.4.
const UNSUPP_VERSION: u8 = 1;

/// Bytes of the common header, per section 7.1.
const HEADER_LEN: usize = 24;

/// Bytes of the MAP payload, per section 11.1.
const MAP_LEN: usize = 36;

/// The largest PCP message, per section 7.
const MAX_LEN: usize = 1100;

/// Bytes of a mapping nonce.
pub(crate) const NONCE_LEN: usize = 12;

/// A PCP MAP request for one IPv4 forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PcpMapRequest {
    /// The client's own address, which the server checks against the packet's source.
    pub(crate) client: Ipv4Addr,
    /// A random value that ties responses and renewals to this client.
    pub(crate) nonce: [u8; NONCE_LEN],
    /// The transport forwarded.
    pub(crate) transport: Transport,
    /// The local port.
    pub(crate) internal: u16,
    /// The external port wanted, zero for any; a renewal names the one granted.
    pub(crate) suggested_port: u16,
    /// The external address wanted, unspecified for any; a renewal names the one granted.
    pub(crate) suggested_ip: Ipv4Addr,
    /// Seconds the mapping should live; zero deletes it.
    pub(crate) lifetime: u32,
}

impl PcpMapRequest {
    /// The request on the wire: a 24-byte header, then the 36-byte MAP payload.
    ///
    /// See RFC 6887 sections 7.1 and 11.1.
    pub(crate) fn encode(&self) -> [u8; HEADER_LEN + MAP_LEN] {
        let mut bytes = [0; HEADER_LEN + MAP_LEN];
        // Header: version, R clear with the opcode, 16 reserved bits.
        bytes[0] = VERSION;
        bytes[1] = OP_MAP;
        bytes[4..8].copy_from_slice(&self.lifetime.to_be_bytes());
        bytes[8..24].copy_from_slice(&self.client.to_ipv6_mapped().octets());
        // MAP payload: nonce, protocol, 24 reserved bits, ports, suggested address.
        bytes[24..36].copy_from_slice(&self.nonce);
        bytes[36] = self.transport.protocol_number();
        bytes[40..42].copy_from_slice(&self.internal.to_be_bytes());
        bytes[42..44].copy_from_slice(&self.suggested_port.to_be_bytes());
        // The unspecified IPv4 address maps to ::ffff:0:0, as section 5 requires.
        bytes[44..60].copy_from_slice(&self.suggested_ip.to_ipv6_mapped().octets());
        bytes
    }

    /// Reads the server's answer to this request.
    ///
    /// The answer must carry this request's nonce, protocol, and internal port.
    ///
    /// # Errors
    ///
    /// Fails on a framing error, another version or opcode, a refusal, or an IPv6 address.
    /// A response to another request also fails, with the fields that differ.
    pub(crate) fn decode_response(&self, bytes: &[u8]) -> Result<PcpMapResponse, CodecError> {
        // Phase 1: version negotiation reads only the first 4 bytes, per section 8.3.
        // A NAT-PMP gateway answers with its 16-bit result 1 there, which reads the same.
        let head = bytes.get(..4).ok_or(CodecError::Truncated {
            expected: 4,
            actual: bytes.len(),
        })?;
        if head[3] == UNSUPP_VERSION && head[0] != VERSION {
            return Err(CodecError::UnsupportedVersion { version: head[0] });
        }

        // Phase 2: framing, then the header.
        if bytes.len() < HEADER_LEN || bytes.len() > MAX_LEN || bytes.len() % 4 != 0 {
            return Err(CodecError::BadLength {
                length: bytes.len(),
            });
        }
        if head[0] != VERSION {
            return Err(CodecError::WrongVersion {
                expected: VERSION,
                actual: head[0],
            });
        }
        if head[1] != RESPONSE | OP_MAP {
            return Err(CodecError::WrongOpcode {
                expected: RESPONSE | OP_MAP,
                actual: head[1],
            });
        }
        if head[3] != 0 {
            return Err(CodecError::Refused {
                protocol: MappingProtocol::Pcp,
                code: head[3].into(),
            });
        }
        let lifetime = Self::u32_at(bytes, 4);
        let epoch = Self::u32_at(bytes, 8);

        // Phase 3: the MAP payload, matched against this request.
        if bytes.len() < HEADER_LEN + MAP_LEN {
            return Err(CodecError::Truncated {
                expected: HEADER_LEN + MAP_LEN,
                actual: bytes.len(),
            });
        }
        let nonce = &bytes[24..36];
        let internal = u16::from_be_bytes([bytes[40], bytes[41]]);
        if nonce != self.nonce
            || bytes[36] != self.transport.protocol_number()
            || internal != self.internal
        {
            return Err(CodecError::Unmatched {
                internal,
                protocol: bytes[36],
            });
        }
        let mut address = [0; 16];
        address.copy_from_slice(&bytes[44..60]);
        let external_ip = Ipv6Addr::from(address)
            .to_ipv4_mapped()
            .ok_or(CodecError::NotIpv4)?;
        Ok(PcpMapResponse {
            lifetime,
            epoch,
            external_port: u16::from_be_bytes([bytes[42], bytes[43]]),
            external_ip,
        })
    }

    /// The big-endian 32-bit number at an offset the caller has bounds-checked.
    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }
}

/// A successful answer to a PCP MAP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PcpMapResponse {
    /// Seconds the mapping lives.
    pub(crate) lifetime: u32,
    /// The server's epoch time, which resets when it loses state.
    pub(crate) epoch: u32,
    /// The external port granted.
    pub(crate) external_port: u16,
    /// The external address granted.
    pub(crate) external_ip: Ipv4Addr,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request to map UDP 9000 from 192.168.1.20, nonce 0x01..0x0c, for 7200 s.
    fn request() -> PcpMapRequest {
        PcpMapRequest {
            client: Ipv4Addr::new(192, 168, 1, 20),
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            transport: Transport::Udp,
            internal: 9000,
            suggested_port: 0,
            suggested_ip: Ipv4Addr::UNSPECIFIED,
            lifetime: 7200,
        }
    }

    /// The server's answer: 203.0.113.7:40000 for 3600 s at epoch 500.
    fn response() -> Vec<u8> {
        let mut bytes = vec![2, 0x81, 0, 0];
        bytes.extend_from_slice(&3600_u32.to_be_bytes());
        bytes.extend_from_slice(&500_u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        bytes.extend_from_slice(&[17, 0, 0, 0]);
        bytes.extend_from_slice(&9000_u16.to_be_bytes());
        bytes.extend_from_slice(&40000_u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7]);
        bytes
    }

    #[test]
    fn map_request_follows_the_rfc_layout() {
        // Sections 7.1 and 11.1, field by field.
        let expected: [u8; 60] = [
            // Version 2, R clear, opcode MAP, reserved.
            2, 1, 0, 0, //
            // Requested lifetime 7200.
            0, 0, 0x1c, 0x20, //
            // Client address ::ffff:192.168.1.20.
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 20, //
            // Mapping nonce.
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, //
            // Protocol 17, reserved.
            17, 0, 0, 0, //
            // Internal port 9000, suggested external port 0.
            0x23, 0x28, 0, 0, //
            // Suggested external address ::ffff:0:0, the IPv4 all-zeros address.
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0,
        ];
        assert_eq!(request().encode(), expected);
    }

    #[test]
    fn map_response_decodes() {
        assert_eq!(
            request().decode_response(&response()),
            Ok(PcpMapResponse {
                lifetime: 3600,
                epoch: 500,
                external_port: 40000,
                external_ip: Ipv4Addr::new(203, 0, 113, 7),
            })
        );
    }

    #[test]
    fn version_negotiation_reports_the_spoken_version() {
        // A NAT-PMP gateway answers version 2 with its own head: version 0, result 1.
        let pmp = [0, 0x81, 0, 1, 0, 0, 0, 9];
        assert_eq!(
            request().decode_response(&pmp),
            Err(CodecError::UnsupportedVersion { version: 0 })
        );
    }

    #[test]
    fn malformed_responses_fail() {
        let ok = response();
        // Three bytes cannot hold the head.
        assert_eq!(
            request().decode_response(&ok[..3]),
            Err(CodecError::Truncated {
                expected: 4,
                actual: 3,
            })
        );
        // 58 bytes is not a multiple of 4.
        assert_eq!(
            request().decode_response(&ok[..58]),
            Err(CodecError::BadLength { length: 58 })
        );
        // 1104 bytes is over the limit.
        let mut long = ok.clone();
        long.resize(1104, 0);
        assert_eq!(
            request().decode_response(&long),
            Err(CodecError::BadLength { length: 1104 })
        );
        // A header alone: well framed, but no MAP payload.
        assert_eq!(
            request().decode_response(&ok[..24]),
            Err(CodecError::Truncated {
                expected: 60,
                actual: 24,
            })
        );
        // The R bit clear: a request, not a response.
        let mut echo = ok.clone();
        echo[1] = 1;
        assert_eq!(
            request().decode_response(&echo),
            Err(CodecError::WrongOpcode {
                expected: 0x81,
                actual: 1,
            })
        );
        // Result 2, NOT_AUTHORIZED.
        let mut refused = ok.clone();
        refused[3] = 2;
        assert_eq!(
            request().decode_response(&refused),
            Err(CodecError::Refused {
                protocol: MappingProtocol::Pcp,
                code: 2,
            })
        );
        // Another nonce: the answer belongs to someone else.
        let mut stranger = ok.clone();
        stranger[24] = 0xee;
        assert_eq!(
            request().decode_response(&stranger),
            Err(CodecError::Unmatched {
                internal: 9000,
                protocol: 17,
            })
        );
        // An IPv6 external address on an IPv4 request.
        let mut v6 = ok;
        v6[44] = 0x20;
        assert_eq!(request().decode_response(&v6), Err(CodecError::NotIpv4));
    }
}
