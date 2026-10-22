//! The network endpoints a record advertises, under the keys of EIP-778.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use axiom_rlp::Decoder;

/// Key of the IPv4 address, 4 bytes.
pub(crate) const KEY_IP: &[u8] = b"ip";

/// Key of the IPv6 address, 16 bytes.
pub(crate) const KEY_IP6: &[u8] = b"ip6";

/// Key of the TCP port, a big-endian integer.
pub(crate) const KEY_TCP: &[u8] = b"tcp";

/// Key of the IPv6-specific TCP port.
pub(crate) const KEY_TCP6: &[u8] = b"tcp6";

/// Key of the UDP port, a big-endian integer.
pub(crate) const KEY_UDP: &[u8] = b"udp";

/// Key of the IPv6-specific UDP port.
pub(crate) const KEY_UDP6: &[u8] = b"udp6";

/// The addresses and ports of a record.
///
/// A malformed value reads as absent.
/// EIP-778 lets records carry any value, so a bad address does not void the record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Endpoints {
    /// The IPv4 address.
    pub ip4: Option<Ipv4Addr>,
    /// The IPv6 address.
    pub ip6: Option<Ipv6Addr>,
    /// The TCP port.
    pub tcp4: Option<u16>,
    /// The IPv6-specific TCP port.
    pub tcp6: Option<u16>,
    /// The UDP port.
    pub udp4: Option<u16>,
    /// The IPv6-specific UDP port.
    pub udp6: Option<u16>,
}

impl Endpoints {
    /// Reads the endpoint keys through a lookup of raw values by key.
    pub(crate) fn read<'a>(value: impl Fn(&[u8]) -> Option<&'a [u8]>) -> Self {
        // Each key decodes on its own; a failure leaves only that field empty.
        Self {
            ip4: value(KEY_IP).and_then(Self::array::<4>).map(Ipv4Addr::from),
            ip6: value(KEY_IP6)
                .and_then(Self::array::<16>)
                .map(Ipv6Addr::from),
            tcp4: value(KEY_TCP).and_then(Self::port),
            tcp6: value(KEY_TCP6).and_then(Self::port),
            udp4: value(KEY_UDP).and_then(Self::port),
            udp6: value(KEY_UDP6).and_then(Self::port),
        }
    }

    /// The IPv4 discovery socket, when the record has an address and a UDP port.
    #[must_use]
    pub fn udp4_socket(&self) -> Option<SocketAddrV4> {
        // Both halves must be present.
        Some(SocketAddrV4::new(self.ip4?, self.udp4?))
    }

    /// The IPv6 discovery socket, falling back to the shared UDP port per EIP-778.
    #[must_use]
    pub fn udp6_socket(&self) -> Option<SocketAddrV6> {
        // No flow label and no scope: records carry neither.
        Some(SocketAddrV6::new(self.ip6?, self.udp6.or(self.udp4)?, 0, 0))
    }

    /// The discovery socket, preferring IPv4.
    #[must_use]
    pub fn udp_socket(&self) -> Option<SocketAddr> {
        // IPv4 first, the family every client supports.
        self.udp4_socket()
            .map(SocketAddr::V4)
            .or_else(|| self.udp6_socket().map(SocketAddr::V6))
    }

    /// The libp2p TCP socket, preferring IPv4.
    #[must_use]
    pub fn tcp_socket(&self) -> Option<SocketAddr> {
        // The IPv6 port falls back to the shared one, as for UDP.
        let v4 = || Some(SocketAddr::new(self.ip4?.into(), self.tcp4?));
        let v6 = || Some(SocketAddr::new(self.ip6?.into(), self.tcp6.or(self.tcp4)?));
        v4().or_else(v6)
    }

    /// A string value of exactly N bytes.
    fn array<const N: usize>(raw: &[u8]) -> Option<[u8; N]> {
        // Exactly one RLP string of the right length.
        let mut decoder = Decoder::new(raw);
        let bytes = decoder.array().ok()?;
        decoder.finish().ok()?;
        Some(bytes)
    }

    /// A port: a canonical integer of at most 16 bits.
    fn port(raw: &[u8]) -> Option<u16> {
        // Exactly one canonical RLP integer.
        let mut decoder = Decoder::new(raw);
        let port = decoder.u16().ok()?;
        decoder.finish().ok()?;
        Some(port)
    }
}
