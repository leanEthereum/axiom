//! Multiaddresses: self-describing, layered network addresses.
//!
//! # Overview
//!
//! A multiaddress is a stack of protocols, outermost first.
//! The text form alternates names and values, the binary form codes and values.
//!
//! ```text
//! text:    /ip4/127.0.0.1/tcp/9000
//!
//! binary:  04 7f 00 00 01    ip4 (code 4), 4 address bytes
//!          06 23 28          tcp (code 6), port 9000 big-endian
//! ```
//!
//! Only the protocols a consensus node dials are supported.
//! See `multiformats/multiaddr` and its protocol table.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use thiserror::Error;

use crate::{
    identity::{PeerId, PeerIdError},
    varint::{Varint, VarintError},
};

/// Multicodec of IPv4.
const CODE_IP4: u64 = 0x04;
/// Multicodec of TCP.
const CODE_TCP: u64 = 0x06;
/// Multicodec of IPv6.
const CODE_IP6: u64 = 0x29;
/// Multicodec of UDP.
const CODE_UDP: u64 = 0x0111;
/// Multicodec of QUIC version 1, RFC 9000.
///
/// The multicodec table gives 0x01cc to the draft-29 QUIC this client never speaks.
const CODE_QUIC_V1: u64 = 0x01cd;
/// Multicodec of a libp2p peer identifier.
const CODE_P2P: u64 = 0x01a5;

/// One layer of a multiaddress.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// An IPv4 address.
    Ip4(Ipv4Addr),
    /// An IPv6 address.
    Ip6(Ipv6Addr),
    /// A TCP port.
    Tcp(u16),
    /// A UDP port.
    Udp(u16),
    /// QUIC version 1, over the UDP layer beneath it.
    QuicV1,
    /// The identity of the node at this address.
    P2p(PeerId),
}

impl Protocol {
    /// Appends the binary encoding of this layer.
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ip4(addr) => {
                Varint::Multiformat.write(CODE_IP4, out);
                out.extend_from_slice(&addr.octets());
            }
            Self::Ip6(addr) => {
                Varint::Multiformat.write(CODE_IP6, out);
                out.extend_from_slice(&addr.octets());
            }
            Self::Tcp(port) => {
                Varint::Multiformat.write(CODE_TCP, out);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Udp(port) => {
                Varint::Multiformat.write(CODE_UDP, out);
                out.extend_from_slice(&port.to_be_bytes());
            }
            // QUIC carries no value: the code alone says it all.
            Self::QuicV1 => Varint::Multiformat.write(CODE_QUIC_V1, out),
            // Variable-size values carry their own varint length.
            Self::P2p(peer) => {
                Varint::Multiformat.write(CODE_P2P, out);
                Varint::Multiformat.write(peer.as_bytes().len() as u64, out);
                out.extend_from_slice(peer.as_bytes());
            }
        }
    }

    /// Reads one layer off the front of the input, advancing past it.
    fn read(input: &mut &[u8]) -> Result<Self, MultiaddrError> {
        // Any malformed varint makes the address unreadable from here on.
        let code = Varint::Multiformat.read(input)?;
        let protocol = match code {
            CODE_IP4 => Self::Ip4(Ipv4Addr::from(Self::read_array::<4>(code, input)?)),
            CODE_IP6 => Self::Ip6(Ipv6Addr::from(Self::read_array::<16>(code, input)?)),
            CODE_TCP | CODE_UDP => {
                let port = u16::from_be_bytes(Self::read_array(code, input)?);
                if code == CODE_TCP {
                    Self::Tcp(port)
                } else {
                    Self::Udp(port)
                }
            }
            CODE_QUIC_V1 => Self::QuicV1,
            CODE_P2P => {
                let len = Varint::Multiformat.read(input)?;
                let truncated = || MultiaddrError::Truncated {
                    code,
                    needed: len,
                    remaining: input.len(),
                };
                let size = usize::try_from(len).map_err(|_| truncated())?;
                let (peer, rest) = input.split_at_checked(size).ok_or_else(truncated)?;
                let peer = PeerId::from_bytes(peer)?;
                *input = rest;
                Self::P2p(peer)
            }
            other => return Err(MultiaddrError::UnknownCode(other)),
        };
        Ok(protocol)
    }

    /// Reads the fixed-size value of the layer with this code off the front of the input.
    fn read_array<const N: usize>(code: u64, input: &mut &[u8]) -> Result<[u8; N], MultiaddrError> {
        let (head, rest) = input
            .split_first_chunk::<N>()
            .ok_or(MultiaddrError::Truncated {
                code,
                needed: N as u64,
                remaining: input.len(),
            })?;
        *input = rest;
        Ok(*head)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip4(addr) => write!(f, "/ip4/{addr}"),
            Self::Ip6(addr) => write!(f, "/ip6/{addr}"),
            Self::Tcp(port) => write!(f, "/tcp/{port}"),
            Self::Udp(port) => write!(f, "/udp/{port}"),
            Self::QuicV1 => f.write_str("/quic-v1"),
            Self::P2p(peer) => write!(f, "/p2p/{peer}"),
        }
    }
}

/// A network address as a stack of protocols, outermost first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Multiaddr {
    /// The layers, outermost first.
    protocols: Vec<Protocol>,
}

impl Multiaddr {
    /// The empty address.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            protocols: Vec::new(),
        }
    }

    /// Appends a layer.
    pub fn push(&mut self, protocol: Protocol) {
        self.protocols.push(protocol);
    }

    /// This address with one more layer.
    #[must_use]
    pub fn with(mut self, protocol: Protocol) -> Self {
        self.push(protocol);
        self
    }

    /// The layers, outermost first.
    #[must_use]
    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    /// The identity named by a trailing peer layer, if any.
    #[must_use]
    pub fn peer_id(&self) -> Option<&PeerId> {
        match self.protocols.last() {
            Some(Protocol::P2p(peer)) => Some(peer),
            _ => None,
        }
    }

    /// The socket address of a TCP address, ignoring a trailing peer layer.
    #[must_use]
    pub const fn tcp_socket_addr(&self) -> Option<SocketAddr> {
        match self.protocols.as_slice() {
            // The socket layers, alone or followed by one peer layer.
            [Protocol::Ip4(ip), Protocol::Tcp(port)]
            | [Protocol::Ip4(ip), Protocol::Tcp(port), Protocol::P2p(_)] => {
                Some(SocketAddr::new(IpAddr::V4(*ip), *port))
            }
            [Protocol::Ip6(ip), Protocol::Tcp(port)]
            | [Protocol::Ip6(ip), Protocol::Tcp(port), Protocol::P2p(_)] => {
                Some(SocketAddr::new(IpAddr::V6(*ip), *port))
            }
            _ => None,
        }
    }

    /// The socket address of a QUIC version 1 address, ignoring a trailing peer layer.
    #[must_use]
    pub const fn quic_socket_addr(&self) -> Option<SocketAddr> {
        match self.protocols.as_slice() {
            [Protocol::Ip4(ip), Protocol::Udp(port), Protocol::QuicV1]
            | [
                Protocol::Ip4(ip),
                Protocol::Udp(port),
                Protocol::QuicV1,
                Protocol::P2p(_),
            ] => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
            [Protocol::Ip6(ip), Protocol::Udp(port), Protocol::QuicV1]
            | [
                Protocol::Ip6(ip),
                Protocol::Udp(port),
                Protocol::QuicV1,
                Protocol::P2p(_),
            ] => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
            _ => None,
        }
    }

    /// The binary encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for protocol in &self.protocols {
            protocol.encode_to(&mut out);
        }
        out
    }

    /// Decodes a binary multiaddress.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, MultiaddrError> {
        let mut protocols = Vec::new();
        // Peel layers off the front until the input runs out.
        while !bytes.is_empty() {
            protocols.push(Protocol::read(&mut bytes)?);
        }
        Ok(Self { protocols })
    }

    /// The QUIC version 1 address of a UDP socket.
    #[must_use]
    pub fn from_quic(addr: SocketAddr) -> Self {
        let ip = match addr.ip() {
            IpAddr::V4(ip) => Protocol::Ip4(ip),
            IpAddr::V6(ip) => Protocol::Ip6(ip),
        };
        Self {
            protocols: vec![ip, Protocol::Udp(addr.port()), Protocol::QuicV1],
        }
    }

    /// The address of a TCP socket.
    #[must_use]
    pub fn from_tcp(addr: SocketAddr) -> Self {
        let ip = match addr.ip() {
            IpAddr::V4(ip) => Protocol::Ip4(ip),
            IpAddr::V6(ip) => Protocol::Ip6(ip),
        };
        Self {
            protocols: vec![ip, Protocol::Tcp(addr.port())],
        }
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for protocol in &self.protocols {
            fmt::Display::fmt(protocol, f)?;
        }
        Ok(())
    }
}

impl FromStr for Multiaddr {
    type Err = MultiaddrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Text must open with a slash: "/ip4/1.2.3.4" splits into ["", "ip4", "1.2.3.4"].
        let mut parts = text.split('/');
        if parts.next() != Some("") {
            return Err(MultiaddrError::MissingLeadingSlash);
        }
        let mut protocols = Vec::new();
        while let Some(name) = parts.next() {
            // Each value-carrying name consumes the part after it.
            let mut value = |protocol| parts.next().ok_or(MultiaddrError::MissingValue(protocol));
            // A value that does not parse names its protocol and keeps its text.
            let invalid = |protocol, value: &str| MultiaddrError::InvalidValue {
                protocol,
                value: value.to_owned(),
            };
            let protocol = match name {
                "ip4" => {
                    let text = value("ip4")?;
                    Protocol::Ip4(text.parse().map_err(|_| invalid("ip4", text))?)
                }
                "ip6" => {
                    let text = value("ip6")?;
                    Protocol::Ip6(text.parse().map_err(|_| invalid("ip6", text))?)
                }
                "tcp" => {
                    let text = value("tcp")?;
                    Protocol::Tcp(text.parse().map_err(|_| invalid("tcp", text))?)
                }
                "udp" => {
                    let text = value("udp")?;
                    Protocol::Udp(text.parse().map_err(|_| invalid("udp", text))?)
                }
                "quic-v1" => Protocol::QuicV1,
                "p2p" => Protocol::P2p(value("p2p")?.parse()?),
                // A trailing slash leaves one empty part, which is tolerated.
                "" if parts.clone().next().is_none() && !protocols.is_empty() => break,
                other => return Err(MultiaddrError::UnknownProtocol(other.to_owned())),
            };
            protocols.push(protocol);
        }
        Ok(Self { protocols })
    }
}

/// A byte string or text that is not a supported multiaddress.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MultiaddrError {
    /// A protocol code or length varint is malformed.
    #[error("malformed multiaddress varint: {0}")]
    Varint(#[from] VarintError),

    /// The binary form ends inside a layer.
    #[error("multiaddress layer {code:#x} needs {needed} bytes but {remaining} remain")]
    Truncated {
        /// Protocol code of the layer.
        code: u64,
        /// Bytes the layer value needs.
        needed: u64,
        /// Bytes left in the input.
        remaining: usize,
    },

    /// A binary layer uses a protocol code this implementation does not know.
    #[error("unknown multiaddress protocol code {0:#x}")]
    UnknownCode(u64),

    /// The text form does not open with a slash.
    ///
    /// The caller holds the text, so the error does not copy it.
    #[error("multiaddress text does not start with a slash")]
    MissingLeadingSlash,

    /// The text form names a protocol this implementation does not know.
    #[error("unknown multiaddress protocol {0:?}")]
    UnknownProtocol(String),

    /// The text form ends where the named protocol expects its value.
    #[error("multiaddress protocol {0} lacks its value")]
    MissingValue(&'static str),

    /// The text form holds a value its protocol cannot parse.
    #[error("invalid {protocol} value {value:?} in multiaddress")]
    InvalidValue {
        /// Name of the protocol.
        protocol: &'static str,
        /// The value text.
        value: String,
    },

    /// A peer layer holds a malformed identifier.
    #[error("malformed peer id layer: {0}")]
    InvalidPeerId(#[from] PeerIdError),
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::identity::PublicKey;

    #[test]
    fn tcp_address_binary_layout() {
        // /ip4/127.0.0.1/tcp/9000 from the module overview.
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();
        assert_eq!(addr.to_bytes(), [0x04, 127, 0, 0, 1, 0x06, 0x23, 0x28]);
        assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/9000");
        assert_eq!(
            addr.tcp_socket_addr(),
            Some("127.0.0.1:9000".parse().unwrap())
        );
    }

    #[test]
    fn spec_examples() {
        // The udp example of the multiaddr README specification section.
        let udp = [0x04, 0x7f, 0x00, 0x00, 0x01, 0x91, 0x02, 0x04, 0xd2];
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/1234".parse().unwrap();
        assert_eq!(addr.to_bytes(), udp);
        assert_eq!(Multiaddr::from_bytes(&udp), Ok(addr.clone()));
        assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/1234");

        // Both scenarios of multiaddr test/multiaddr.feature: 192.0.2.42 is c000022a, port 443 is 01bb.
        let tcp = [0x04, 0xc0, 0x00, 0x02, 0x2a, 0x06, 0x01, 0xbb];
        let addr: Multiaddr = "/ip4/192.0.2.42/tcp/443".parse().unwrap();
        assert_eq!(addr.to_bytes(), tcp);
        assert_eq!(Multiaddr::from_bytes(&tcp), Ok(addr.clone()));
        assert_eq!(addr.to_string(), "/ip4/192.0.2.42/tcp/443");
        // The string form is 23 bytes, the packed form 8.
        assert_eq!(addr.to_string().len(), 23);
        assert_eq!(addr.to_bytes().len(), 8);
    }

    #[test]
    fn codes_match_the_protocol_table() {
        // Codes from multiaddr protocols.csv and the multicodec table.
        let cases = [
            (Protocol::Ip4(Ipv4Addr::UNSPECIFIED), 4),
            (Protocol::Tcp(0), 6),
            (Protocol::Ip6(Ipv6Addr::UNSPECIFIED), 41),
            (Protocol::Udp(0), 273),
            (Protocol::QuicV1, 461),
        ];
        for (protocol, code) in cases {
            // Each layer opens with its code as a varint.
            let mut bytes = Vec::new();
            protocol.encode_to(&mut bytes);
            assert_eq!(Varint::Multiformat.read(&mut &bytes[..]), Ok(code));
        }
        // The p2p code is 421, read off the front of an encoded peer layer.
        let peer = PeerId::from_public_key(&PublicKey::secp256k1([2; 33]));
        let mut bytes = Vec::new();
        Protocol::P2p(peer).encode_to(&mut bytes);
        assert_eq!(Varint::Multiformat.read(&mut &bytes[..]), Ok(421));
    }

    #[test]
    fn quic_address_binary_layout() {
        // udp is code 0x0111, varint [0x91, 0x02]; quic-v1 is 0x01cd, varint [0xcd, 0x03].
        let addr: Multiaddr = "/ip6/::1/udp/9001/quic-v1".parse().unwrap();
        let mut expected = vec![0x29];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&[0x91, 0x02, 0x23, 0x29, 0xcd, 0x03]);
        assert_eq!(addr.to_bytes(), expected);
        assert_eq!(Multiaddr::from_bytes(&expected), Ok(addr.clone()));
        // A QUIC address is not a TCP socket.
        assert_eq!(addr.tcp_socket_addr(), None);
    }

    #[test]
    fn quic_socket_addresses() {
        // The QUIC form of a socket round-trips through its socket address.
        let socket: SocketAddr = "192.0.2.7:9000".parse().unwrap();
        let address = Multiaddr::from_quic(socket);
        assert_eq!(address.to_string(), "/ip4/192.0.2.7/udp/9000/quic-v1");
        assert_eq!(address.quic_socket_addr(), Some(socket));
        assert_eq!(address.tcp_socket_addr(), None);

        // A trailing peer layer is ignored; IPv6 works the same way.
        let peer = PeerId::from_public_key(&PublicKey::secp256k1([2; 33]));
        let with_peer = address.with(Protocol::P2p(peer));
        assert_eq!(with_peer.quic_socket_addr(), Some(socket));
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(Multiaddr::from_quic(v6).quic_socket_addr(), Some(v6));

        // Plain UDP without the QUIC layer is not a QUIC address.
        let udp: Multiaddr = "/ip4/192.0.2.7/udp/9000".parse().unwrap();
        assert_eq!(udp.quic_socket_addr(), None);
    }

    #[test]
    fn peer_layer_round_trips() {
        // After 8 bytes of ip4 and tcp, a 39-byte secp256k1 identifier takes p2p code [0xa5, 0x03] and length 0x27.
        let peer = PeerId::from_public_key(&PublicKey::secp256k1([2; 33]));
        let addr = Multiaddr::from_tcp("10.0.0.1:13000".parse().unwrap())
            .with(Protocol::P2p(peer.clone()));
        let bytes = addr.to_bytes();
        assert_eq!(&bytes[8..11], &[0xa5, 0x03, 0x27]);
        assert_eq!(Multiaddr::from_bytes(&bytes), Ok(addr.clone()));
        assert_eq!(addr.to_string().parse::<Multiaddr>(), Ok(addr.clone()));
        assert_eq!(addr.peer_id(), Some(&peer));
        // The peer layer does not hide the socket address.
        assert_eq!(
            addr.tcp_socket_addr(),
            Some("10.0.0.1:13000".parse().unwrap())
        );
    }

    #[test]
    fn rejects_malformed() {
        // Missing port value.
        assert_eq!(
            "/ip4/1.2.3.4/tcp".parse::<Multiaddr>(),
            Err(MultiaddrError::MissingValue("tcp"))
        );
        // Port above 65535.
        assert_eq!(
            "/tcp/70000".parse::<Multiaddr>(),
            Err(MultiaddrError::InvalidValue {
                protocol: "tcp",
                value: "70000".into()
            })
        );
        // No leading slash.
        assert_eq!(
            "ip4/1.2.3.4".parse::<Multiaddr>(),
            Err(MultiaddrError::MissingLeadingSlash)
        );
        // A protocol name this implementation does not know.
        assert_eq!(
            "/dns4/example.org".parse::<Multiaddr>(),
            Err(MultiaddrError::UnknownProtocol("dns4".into()))
        );
        // Code 0x35 is dns, not supported here.
        assert_eq!(
            Multiaddr::from_bytes(&[0x35, 0x00]),
            Err(MultiaddrError::UnknownCode(0x35))
        );
        // An ip4 layer with 3 of its 4 bytes.
        assert_eq!(
            Multiaddr::from_bytes(&[0x04, 1, 2, 3]),
            Err(MultiaddrError::Truncated {
                code: 0x04,
                needed: 4,
                remaining: 3
            })
        );
        // A p2p layer declaring 39 bytes with 1 present.
        assert_eq!(
            Multiaddr::from_bytes(&[0xa5, 0x03, 0x27, 0x00]),
            Err(MultiaddrError::Truncated {
                code: 0x01a5,
                needed: 39,
                remaining: 1
            })
        );
        // A protocol code cut inside its varint.
        assert_eq!(
            Multiaddr::from_bytes(&[0xa5]),
            Err(MultiaddrError::Varint(VarintError::Truncated { len: 1 }))
        );
    }

    /// Strategy over every supported layer.
    fn protocol() -> impl Strategy<Value = Protocol> {
        prop_oneof![
            any::<[u8; 4]>().prop_map(|o| Protocol::Ip4(Ipv4Addr::from(o))),
            any::<[u8; 16]>().prop_map(|o| Protocol::Ip6(Ipv6Addr::from(o))),
            any::<u16>().prop_map(Protocol::Tcp),
            any::<u16>().prop_map(Protocol::Udp),
            Just(Protocol::QuicV1),
            any::<[u8; 32]>().prop_map(|p| {
                let mut key = [2u8; 33];
                key[1..].copy_from_slice(&p);
                Protocol::P2p(PeerId::from_public_key(&PublicKey::secp256k1(key)))
            }),
        ]
    }

    proptest! {
        #[test]
        fn round_trip(protocols in proptest::collection::vec(protocol(), 0..6)) {
            let addr = Multiaddr { protocols };
            prop_assert_eq!(Multiaddr::from_bytes(&addr.to_bytes()), Ok(addr.clone()));
            prop_assert_eq!(addr.to_string().parse::<Multiaddr>(), Ok(addr));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64), text in "\\PC{0,64}") {
            let _ = Multiaddr::from_bytes(&bytes);
            let _ = text.parse::<Multiaddr>();
        }
    }
}
