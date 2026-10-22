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
    varint,
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
const CODE_QUIC_V1: u64 = 0x01cc;
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
                varint::encode(CODE_IP4, out);
                out.extend_from_slice(&addr.octets());
            }
            Self::Ip6(addr) => {
                varint::encode(CODE_IP6, out);
                out.extend_from_slice(&addr.octets());
            }
            Self::Tcp(port) => {
                varint::encode(CODE_TCP, out);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Udp(port) => {
                varint::encode(CODE_UDP, out);
                out.extend_from_slice(&port.to_be_bytes());
            }
            // QUIC carries no value: the code alone says it all.
            Self::QuicV1 => varint::encode(CODE_QUIC_V1, out),
            // Variable-size values carry their own varint length.
            Self::P2p(peer) => {
                varint::encode(CODE_P2P, out);
                varint::encode(peer.as_bytes().len() as u64, out);
                out.extend_from_slice(peer.as_bytes());
            }
        }
    }

    /// Decodes one layer, returning it and the bytes it took.
    fn decode(bytes: &[u8]) -> Result<(Self, usize), MultiaddrError> {
        let (code, mut at) = varint::decode_multiformat(bytes)
            .ok()
            .flatten()
            .ok_or(MultiaddrError::Truncated)?;
        // Takes the next fixed-size value off the input.
        let take = |at: usize, len: usize| bytes.get(at..at + len).ok_or(MultiaddrError::Truncated);
        let protocol = match code {
            CODE_IP4 => {
                let octets: [u8; 4] = take(at, 4)?
                    .try_into()
                    .map_err(|_| MultiaddrError::Truncated)?;
                at += 4;
                Self::Ip4(Ipv4Addr::from(octets))
            }
            CODE_IP6 => {
                let octets: [u8; 16] = take(at, 16)?
                    .try_into()
                    .map_err(|_| MultiaddrError::Truncated)?;
                at += 16;
                Self::Ip6(Ipv6Addr::from(octets))
            }
            CODE_TCP | CODE_UDP => {
                let port = take(at, 2)?;
                let port = u16::from_be_bytes([port[0], port[1]]);
                at += 2;
                if code == CODE_TCP {
                    Self::Tcp(port)
                } else {
                    Self::Udp(port)
                }
            }
            CODE_QUIC_V1 => Self::QuicV1,
            CODE_P2P => {
                let (len, len_len) = varint::decode_multiformat(&bytes[at..])
                    .ok()
                    .flatten()
                    .ok_or(MultiaddrError::Truncated)?;
                at += len_len;
                let len = usize::try_from(len).map_err(|_| MultiaddrError::Truncated)?;
                let peer = PeerId::from_bytes(take(at, len)?)?;
                at += len;
                Self::P2p(peer)
            }
            other => return Err(MultiaddrError::UnknownCode(other)),
        };
        Ok((protocol, at))
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
            [Protocol::Ip4(ip), Protocol::Tcp(port), rest @ ..] if is_peer_suffix(rest) => {
                Some(SocketAddr::new(IpAddr::V4(*ip), *port))
            }
            [Protocol::Ip6(ip), Protocol::Tcp(port), rest @ ..] if is_peer_suffix(rest) => {
                Some(SocketAddr::new(IpAddr::V6(*ip), *port))
            }
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
            let (protocol, len) = Protocol::decode(bytes)?;
            protocols.push(protocol);
            bytes = &bytes[len..];
        }
        Ok(Self { protocols })
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

/// Whether the layers after a socket address are empty or one peer layer.
const fn is_peer_suffix(rest: &[Protocol]) -> bool {
    matches!(rest, [] | [Protocol::P2p(_)])
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
            return Err(MultiaddrError::InvalidText);
        }
        let mut protocols = Vec::new();
        while let Some(name) = parts.next() {
            // Each value-carrying name consumes the part after it.
            let mut value = || parts.next().ok_or(MultiaddrError::InvalidText);
            let protocol = match name {
                "ip4" => Protocol::Ip4(value()?.parse().map_err(|_| MultiaddrError::InvalidText)?),
                "ip6" => Protocol::Ip6(value()?.parse().map_err(|_| MultiaddrError::InvalidText)?),
                "tcp" => Protocol::Tcp(value()?.parse().map_err(|_| MultiaddrError::InvalidText)?),
                "udp" => Protocol::Udp(value()?.parse().map_err(|_| MultiaddrError::InvalidText)?),
                "quic-v1" => Protocol::QuicV1,
                "p2p" => Protocol::P2p(value()?.parse()?),
                // A trailing slash leaves one empty part, which is tolerated.
                "" if parts.clone().next().is_none() && !protocols.is_empty() => break,
                _ => return Err(MultiaddrError::InvalidText),
            };
            protocols.push(protocol);
        }
        Ok(Self { protocols })
    }
}

/// A byte string or text that is not a supported multiaddress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MultiaddrError {
    /// The binary form ends inside a layer.
    #[error("multiaddress ends inside a layer")]
    Truncated,

    /// A binary layer uses a protocol code this implementation does not know.
    #[error("unknown multiaddress protocol code {0:#x}")]
    UnknownCode(u64),

    /// The text form names an unknown protocol or holds a malformed value.
    #[error("malformed multiaddress text")]
    InvalidText,

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
    fn quic_address_binary_layout() {
        // udp is code 0x0111 → varint [0x91, 0x02]; quic-v1 is 0x01cc → [0xcc, 0x03].
        let addr: Multiaddr = "/ip6/::1/udp/9001/quic-v1".parse().unwrap();
        let mut expected = vec![0x29];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&[0x91, 0x02, 0x23, 0x29, 0xcc, 0x03]);
        assert_eq!(addr.to_bytes(), expected);
        assert_eq!(Multiaddr::from_bytes(&expected), Ok(addr.clone()));
        // A QUIC address is not a TCP socket.
        assert_eq!(addr.tcp_socket_addr(), None);
    }

    #[test]
    fn peer_layer_round_trips() {
        // After 8 bytes of ip4 and tcp, a 39-byte secp256k1 identifier → p2p code [0xa5, 0x03], length 0x27.
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
            Err(MultiaddrError::InvalidText)
        );
        // Port above 65535.
        assert_eq!(
            "/tcp/70000".parse::<Multiaddr>(),
            Err(MultiaddrError::InvalidText)
        );
        // No leading slash.
        assert_eq!(
            "ip4/1.2.3.4".parse::<Multiaddr>(),
            Err(MultiaddrError::InvalidText)
        );
        // Code 0x35 is dns, not supported here.
        assert_eq!(
            Multiaddr::from_bytes(&[0x35, 0x00]),
            Err(MultiaddrError::UnknownCode(0x35))
        );
        // An ip4 layer with 3 of its 4 bytes.
        assert_eq!(
            Multiaddr::from_bytes(&[0x04, 1, 2, 3]),
            Err(MultiaddrError::Truncated)
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
