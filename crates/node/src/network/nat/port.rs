//! The ports the node listens on, and the transports they carry.

use std::{fmt, net::Ipv4Addr};

use super::session::UPNP_LEASE;

/// A transport a gateway forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Transport {
    /// The NAT-PMP mapping opcode: 1 maps UDP, 2 maps TCP.
    ///
    /// See RFC 6886 section 3.3.
    pub(crate) const fn pmp_opcode(self) -> u8 {
        match self {
            Self::Udp => 1,
            Self::Tcp => 2,
        }
    }

    /// The value of the UPnP protocol argument.
    ///
    /// See the PortMappingProtocol state variable of WANIPConnection.
    pub(crate) const fn upnp_name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// A socket the node listens on, as the record names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Listener {
    /// The libp2p TCP listener: the record's tcp entry.
    Libp2pTcp,
    /// The libp2p QUIC listener: the record's quic entry.
    Libp2pQuic,
    /// The discv5 socket: the record's udp entry.
    Discovery,
}

impl Listener {
    /// The transport the listener speaks.
    pub(crate) const fn transport(self) -> Transport {
        match self {
            Self::Libp2pTcp => Transport::Tcp,
            Self::Libp2pQuic | Self::Discovery => Transport::Udp,
        }
    }

    /// A short name for logs and the UPnP mapping description.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Libp2pTcp => "libp2p-tcp",
            Self::Libp2pQuic => "libp2p-quic",
            Self::Discovery => "discv5",
        }
    }
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The local ports to forward; any of them may be absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ListenPorts {
    /// The libp2p TCP port.
    pub(crate) tcp: Option<u16>,
    /// The libp2p QUIC port.
    pub(crate) quic: Option<u16>,
    /// The discv5 UDP port.
    pub(crate) discovery: Option<u16>,
}

impl ListenPorts {
    /// Each listener with its port, in a fixed order.
    ///
    /// A QUIC listener sharing the discovery port appears once, as discovery.
    /// One UDP socket cannot be forwarded twice.
    pub(crate) fn listeners(self) -> Vec<(Listener, u16)> {
        let mut listeners = Vec::new();
        if let Some(port) = self.tcp {
            listeners.push((Listener::Libp2pTcp, port));
        }
        if let Some(port) = self.discovery {
            listeners.push((Listener::Discovery, port));
        }
        if let Some(port) = self.quic
            && self.discovery != Some(port)
        {
            listeners.push((Listener::Libp2pQuic, port));
        }
        listeners
    }
}

/// The longest lifetime a renewal schedule trusts.
///
/// A gateway may grant any 32-bit lifetime; a day bounds how long a lost mapping goes unnoticed.
const MAX_LIFETIME: u32 = 24 * 3600;

/// One forwarding the gateway granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Forwarding {
    /// The listener forwarded.
    pub(crate) listener: Listener,
    /// The local port.
    pub(crate) internal: u16,
    /// The port on the gateway's external address.
    pub(crate) external: u16,
    /// Seconds the gateway keeps it, zero for a permanent lease.
    pub(crate) lifetime: u32,
}

impl Forwarding {
    /// The lifetime a renewal schedule trusts: zero means permanent, and an absurd one is capped.
    pub(crate) fn schedule_lifetime(&self) -> u32 {
        if self.lifetime == 0 {
            UPNP_LEASE
        } else {
            self.lifetime.min(MAX_LIFETIME)
        }
    }
}

/// The external address a gateway reports, and the ports it forwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MappedEndpoint {
    /// The gateway's external IPv4 address.
    pub(crate) ip: Ipv4Addr,
    /// The external libp2p TCP port, when forwarded.
    pub(crate) tcp: Option<u16>,
    /// The external discv5 UDP port, when forwarded.
    pub(crate) udp: Option<u16>,
    /// The external libp2p QUIC port, when forwarded.
    pub(crate) quic: Option<u16>,
}

impl MappedEndpoint {
    /// The endpoint a set of forwardings gives on an external address.
    pub(crate) fn new(ip: Ipv4Addr, forwardings: &[Forwarding]) -> Self {
        let port = |listener| {
            forwardings
                .iter()
                .find(|forwarding| forwarding.listener == listener)
                .map(|forwarding| forwarding.external)
        };
        Self {
            ip,
            tcp: port(Listener::Libp2pTcp),
            udp: port(Listener::Discovery),
            quic: port(Listener::Libp2pQuic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners_skip_absent_ports_and_a_shared_udp_socket() {
        // All three ports distinct: three listeners, TCP first.
        let ports = ListenPorts {
            tcp: Some(9000),
            quic: Some(9001),
            discovery: Some(9002),
        };
        assert_eq!(
            ports.listeners(),
            [
                (Listener::Libp2pTcp, 9000),
                (Listener::Discovery, 9002),
                (Listener::Libp2pQuic, 9001),
            ]
        );
        // QUIC on the discovery port: one UDP forwarding serves both.
        let shared = ListenPorts {
            tcp: None,
            quic: Some(9000),
            discovery: Some(9000),
        };
        assert_eq!(shared.listeners(), [(Listener::Discovery, 9000)]);
        // Nothing to forward.
        assert_eq!(ListenPorts::default().listeners(), []);
    }

    #[test]
    fn schedules_trust_only_sane_lifetimes() {
        let forwarding = |lifetime| Forwarding {
            listener: Listener::Discovery,
            internal: 9000,
            external: 9000,
            lifetime,
        };
        // Permanent leases renew hourly; ten years is cut to a day.
        assert_eq!(forwarding(0).schedule_lifetime(), 3600);
        assert_eq!(forwarding(7200).schedule_lifetime(), 7200);
        assert_eq!(forwarding(315_360_000).schedule_lifetime(), 86_400);
    }
}
