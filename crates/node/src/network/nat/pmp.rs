//! NAT-PMP messages, version 0, as RFC 6886 lays them out.
//!
//! Every number is big-endian; addresses go in network order.

use std::net::Ipv4Addr;

use super::{CodecError, MappingProtocol, Transport};

/// The NAT-PMP version byte.
const VERSION: u8 = 0;

/// The opcode asking for the external address, per RFC 6886 section 3.2.
const OP_EXTERNAL_ADDRESS: u8 = 0;

/// The bit a gateway sets on a request's opcode to mark the response.
const RESPONSE: u8 = 128;

/// The result code of a gateway that does not speak the version sent.
const UNSUPPORTED_VERSION: u16 = 1;

/// A NAT-PMP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PmpRequest {
    /// Asks for the gateway's external address.
    ExternalAddress,
    /// Asks for a mapping, or deletes one with a zero lifetime.
    Map {
        /// The transport forwarded.
        transport: Transport,
        /// The local port.
        internal: u16,
        /// The external port wanted; a renewal names the one granted.
        suggested: u16,
        /// Seconds the mapping should live.
        lifetime: u32,
    },
}

impl PmpRequest {
    /// The request on the wire: 2 bytes for the address, 12 for a mapping.
    ///
    /// See RFC 6886 sections 3.2 and 3.3.
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::ExternalAddress => vec![VERSION, OP_EXTERNAL_ADDRESS],
            Self::Map {
                transport,
                internal,
                suggested,
                lifetime,
            } => {
                let mut bytes = Vec::with_capacity(12);
                // Version, opcode, then 16 reserved bits sent as zero.
                bytes.extend_from_slice(&[VERSION, transport.pmp_opcode(), 0, 0]);
                bytes.extend_from_slice(&internal.to_be_bytes());
                bytes.extend_from_slice(&suggested.to_be_bytes());
                bytes.extend_from_slice(&lifetime.to_be_bytes());
                bytes
            }
        }
    }

    /// The deletion of a mapping: zero lifetime and zero suggested port.
    ///
    /// See RFC 6886 section 3.4.
    pub(crate) const fn delete(transport: Transport, internal: u16) -> Self {
        Self::Map {
            transport,
            internal,
            suggested: 0,
            lifetime: 0,
        }
    }

    /// The response opcode this request calls for.
    const fn response_opcode(self) -> u8 {
        match self {
            Self::ExternalAddress => RESPONSE | OP_EXTERNAL_ADDRESS,
            Self::Map { transport, .. } => RESPONSE | transport.pmp_opcode(),
        }
    }

    /// Reads the gateway's answer to this request.
    ///
    /// # Errors
    ///
    /// Fails on another version, another opcode, a short message, or a refusal.
    pub(crate) fn decode_response(self, bytes: &[u8]) -> Result<PmpResponse, CodecError> {
        // Phase 1: the common head of 8 bytes: version, opcode, result, epoch.
        let head = Self::field::<8>(bytes, 0)?;
        let code = u16::from_be_bytes([head[2], head[3]]);
        // An unsupported-version answer carries only the head; its version is the one spoken.
        if code == UNSUPPORTED_VERSION {
            return Err(CodecError::UnsupportedVersion { version: head[0] });
        }
        if head[0] != VERSION {
            return Err(CodecError::WrongVersion {
                expected: VERSION,
                actual: head[0],
            });
        }
        let expected = self.response_opcode();
        if head[1] != expected {
            return Err(CodecError::WrongOpcode {
                expected,
                actual: head[1],
            });
        }
        if code != 0 {
            return Err(CodecError::Refused {
                protocol: MappingProtocol::NatPmp,
                code,
            });
        }
        let epoch = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);

        // Phase 2: the opcode-specific body.
        match self {
            Self::ExternalAddress => Ok(PmpResponse::ExternalAddress {
                epoch,
                address: Ipv4Addr::from(Self::field::<4>(bytes, 8)?),
            }),
            Self::Map { .. } => {
                let body = Self::field::<8>(bytes, 8)?;
                Ok(PmpResponse::Map {
                    epoch,
                    internal: u16::from_be_bytes([body[0], body[1]]),
                    external: u16::from_be_bytes([body[2], body[3]]),
                    lifetime: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                })
            }
        }
    }

    /// The N bytes at an offset, or the length the message lacks.
    fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], CodecError> {
        bytes
            .get(offset..offset + N)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(CodecError::Truncated {
                expected: offset + N,
                actual: bytes.len(),
            })
    }
}

/// A successful NAT-PMP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PmpResponse {
    /// The gateway's external address.
    ExternalAddress {
        /// Seconds since the gateway's mapping table was reset.
        epoch: u32,
        /// The external IPv4 address.
        address: Ipv4Addr,
    },
    /// A mapping granted, or deleted when its lifetime is zero.
    Map {
        /// Seconds since the gateway's mapping table was reset.
        epoch: u32,
        /// The local port the mapping serves.
        internal: u16,
        /// The external port granted.
        external: u16,
        /// Seconds the mapping lives.
        lifetime: u32,
    },
}

impl PmpResponse {
    /// The gateway's epoch, which resets when it loses its mappings.
    pub(crate) const fn epoch(self) -> u32 {
        match self {
            Self::ExternalAddress { epoch, .. } | Self::Map { epoch, .. } => epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_follow_the_rfc_layouts() {
        // Section 3.2: version 0, opcode 0.
        assert_eq!(PmpRequest::ExternalAddress.encode(), [0, 0]);
        // Section 3.3: map TCP 9000 to suggested 9000 for 7200 s.
        //
        //     00 02 0000 | 2328 2328 | 00001c20
        let map = PmpRequest::Map {
            transport: Transport::Tcp,
            internal: 9000,
            suggested: 9000,
            lifetime: 7200,
        };
        assert_eq!(
            map.encode(),
            [0, 2, 0, 0, 0x23, 0x28, 0x23, 0x28, 0, 0, 0x1c, 0x20]
        );
        // Section 3.4: delete UDP 9001, with zero suggested port and lifetime.
        assert_eq!(
            PmpRequest::delete(Transport::Udp, 9001).encode(),
            [0, 1, 0, 0, 0x23, 0x29, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn external_address_response_decodes() {
        // Opcode 128, result 0, epoch 1000, address 203.0.113.7.
        let bytes = [0, 128, 0, 0, 0, 0, 0x03, 0xe8, 203, 0, 113, 7];
        assert_eq!(
            PmpRequest::ExternalAddress.decode_response(&bytes),
            Ok(PmpResponse::ExternalAddress {
                epoch: 1000,
                address: Ipv4Addr::new(203, 0, 113, 7),
            })
        );
    }

    #[test]
    fn map_response_decodes() {
        // Opcode 130 for TCP, epoch 60, internal 9000, external 40000, lifetime 3600.
        let bytes = [
            0, 130, 0, 0, 0, 0, 0, 60, 0x23, 0x28, 0x9c, 0x40, 0, 0, 0x0e, 0x10,
        ];
        let request = PmpRequest::Map {
            transport: Transport::Tcp,
            internal: 9000,
            suggested: 9000,
            lifetime: 7200,
        };
        assert_eq!(
            request.decode_response(&bytes),
            Ok(PmpResponse::Map {
                epoch: 60,
                internal: 9000,
                external: 40000,
                lifetime: 3600,
            })
        );
    }

    #[test]
    fn malformed_and_refused_responses_fail() {
        let tcp = PmpRequest::Map {
            transport: Transport::Tcp,
            internal: 9000,
            suggested: 9000,
            lifetime: 7200,
        };
        let ok = [
            0, 130, 0, 0, 0, 0, 0, 60, 0x23, 0x28, 0x9c, 0x40, 0, 0, 0x0e, 0x10,
        ];
        // A head of seven bytes.
        assert_eq!(
            tcp.decode_response(&ok[..7]),
            Err(CodecError::Truncated {
                expected: 8,
                actual: 7,
            })
        );
        // A mapping body cut at 15 bytes.
        assert_eq!(
            tcp.decode_response(&ok[..15]),
            Err(CodecError::Truncated {
                expected: 16,
                actual: 15,
            })
        );
        // The UDP answer to a TCP request.
        let mut udp = ok;
        udp[1] = 129;
        assert_eq!(
            tcp.decode_response(&udp),
            Err(CodecError::WrongOpcode {
                expected: 130,
                actual: 129,
            })
        );
        // Version 2 with a success code: another protocol.
        let mut other = ok;
        other[0] = 2;
        assert_eq!(
            tcp.decode_response(&other),
            Err(CodecError::WrongVersion {
                expected: 0,
                actual: 2,
            })
        );
        // Result 2, not authorized, from section 3.5.
        let mut refused = ok;
        refused[3] = 2;
        assert_eq!(
            tcp.decode_response(&refused),
            Err(CodecError::Refused {
                protocol: MappingProtocol::NatPmp,
                code: 2,
            })
        );
        // Result 1, unsupported version, from a gateway that speaks version 0 only.
        let unsupported = [0, 130, 0, 1, 0, 0, 0, 60];
        assert_eq!(
            tcp.decode_response(&unsupported),
            Err(CodecError::UnsupportedVersion { version: 0 })
        );
    }
}
