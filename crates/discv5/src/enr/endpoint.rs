//! The network endpoints a record advertises, under the keys of EIP-778.
//!
//! The QUIC keys come from the consensus p2p specification, "ENR structure" in phase0.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::raw_value::RawValue;

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

/// Key of the libp2p QUIC port, a big-endian integer.
pub(crate) const KEY_QUIC: &[u8] = b"quic";

/// Key of the IPv6-specific libp2p QUIC port.
pub(crate) const KEY_QUIC6: &[u8] = b"quic6";

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
    /// The libp2p QUIC port.
    pub quic4: Option<u16>,
    /// The IPv6-specific libp2p QUIC port.
    pub quic6: Option<u16>,
}

impl Endpoints {
    /// Reads the endpoint keys through a lookup of raw values by key.
    pub(crate) fn read<'a>(value: impl Fn(&[u8]) -> Option<&'a [u8]>) -> Self {
        // Each key decodes on its own; a failure leaves only that field empty.
        Self {
            ip4: value(KEY_IP)
                .and_then(|raw| RawValue(raw).array::<4>())
                .map(Ipv4Addr::from),
            ip6: value(KEY_IP6)
                .and_then(|raw| RawValue(raw).array::<16>())
                .map(Ipv6Addr::from),
            tcp4: value(KEY_TCP).and_then(|raw| RawValue(raw).port()),
            tcp6: value(KEY_TCP6).and_then(|raw| RawValue(raw).port()),
            udp4: value(KEY_UDP).and_then(|raw| RawValue(raw).port()),
            udp6: value(KEY_UDP6).and_then(|raw| RawValue(raw).port()),
            quic4: value(KEY_QUIC).and_then(|raw| RawValue(raw).port()),
            quic6: value(KEY_QUIC6).and_then(|raw| RawValue(raw).port()),
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

    /// The libp2p QUIC socket, preferring IPv4.
    #[must_use]
    pub fn quic_socket(&self) -> Option<SocketAddr> {
        // The IPv6 port falls back to the shared one, as for TCP and UDP.
        let v4 = || Some(SocketAddr::new(self.ip4?.into(), self.quic4?));
        let v6 = || {
            Some(SocketAddr::new(
                self.ip6?.into(),
                self.quic6.or(self.quic4)?,
            ))
        };
        v4().or_else(v6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Endpoints read from a list of key and value pairs.
    fn read(pairs: &[(&[u8], &[u8])]) -> Endpoints {
        Endpoints::read(|key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, value)| *value)
        })
    }

    #[test]
    fn quic_sockets_prefer_ipv4_and_share_the_port() {
        // 10.0.0.1 with QUIC on 9001, as RLP items: the IPv4 socket.
        let v4 = read(&[
            (KEY_IP, &[0x84, 10, 0, 0, 1]),
            (KEY_QUIC, &[0x82, 0x23, 0x29]),
        ]);
        assert_eq!(
            v4.quic_socket(),
            Some(SocketAddr::from(([10, 0, 0, 1], 9001)))
        );

        // An IPv6-only record uses quic6, or else the shared quic port.
        let ip6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        // Values are raw RLP items: a 16-byte string takes the prefix 0x90.
        let mut ip6_item = vec![0x90];
        ip6_item.extend_from_slice(&ip6);
        let v6 = read(&[(KEY_IP6, &ip6_item), (KEY_QUIC, &[0x82, 0x23, 0x29])]);
        assert_eq!(v6.quic_socket(), Some(SocketAddr::from((ip6, 9001))));
        let v6 = read(&[
            (KEY_IP6, &ip6_item),
            (KEY_QUIC, &[0x82, 0x23, 0x29]),
            (KEY_QUIC6, &[0x82, 0x23, 0x2a]),
        ]);
        assert_eq!(v6.quic_socket(), Some(SocketAddr::from((ip6, 9002))));

        // No QUIC port, no QUIC socket, even with TCP.
        let tcp = read(&[
            (KEY_IP, &[0x84, 10, 0, 0, 1]),
            (KEY_TCP, &[0x82, 0x23, 0x28]),
        ]);
        assert_eq!(tcp.quic_socket(), None);
        assert_eq!(
            tcp.tcp_socket(),
            Some(SocketAddr::from(([10, 0, 0, 1], 9000)))
        );
    }
}
