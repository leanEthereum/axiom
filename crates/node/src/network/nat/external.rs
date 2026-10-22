//! The endpoint the node advertises, from what the gateway and the peers report.

use std::net::{Ipv4Addr, SocketAddrV4};

use axiom_discv5::{EnrBuilder, enr::Endpoints};

use super::MappedEndpoint;

/// The address and ports the record states for this node.
///
/// An absent port leaves the record's own entry in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdvertisedEndpoint {
    /// The ip entry.
    pub(crate) ip: Ipv4Addr,
    /// The udp entry: the discv5 port.
    pub(crate) udp: Option<u16>,
    /// The tcp entry: the libp2p TCP port.
    pub(crate) tcp: Option<u16>,
    /// The quic entry: the libp2p QUIC port.
    pub(crate) quic: Option<u16>,
}

impl AdvertisedEndpoint {
    /// Whether a record's endpoints already state all of this.
    pub(crate) fn is_stated_by(&self, endpoints: &Endpoints) -> bool {
        let agrees = |port: Option<u16>, entry: Option<u16>| port.is_none() || port == entry;
        endpoints.ip4 == Some(self.ip)
            && agrees(self.udp, endpoints.udp4)
            && agrees(self.tcp, endpoints.tcp4)
            && agrees(self.quic, endpoints.quic4)
    }

    /// Writes the entries into a record under construction, replacing earlier values.
    pub(crate) fn write(self, mut builder: EnrBuilder) -> EnrBuilder {
        builder = builder.ip4(self.ip);
        if let Some(port) = self.udp {
            builder = builder.udp4(port);
        }
        if let Some(port) = self.tcp {
            builder = builder.tcp4(port);
        }
        if let Some(port) = self.quic {
            builder = builder.quic4(port);
        }
        builder
    }
}

/// What the node knows of its external endpoint, from the two sources.
///
/// # Overview
///
/// Peers' votes say what the internet sees, so their address wins.
/// Behind two NATs, the home gateway reports an address of the provider's NAT, which no peer reaches.
/// The gateway's address counts only when it is publicly routable.
///
/// Ports follow the source of the address:
///
/// - The udp port is the voted one, else the mapped one.
/// - The tcp and quic ports are the mapped ones, when the gateway's address is the advertised one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExternalAddress {
    /// The endpoint peers' PONG votes confirmed.
    voted: Option<SocketAddrV4>,
    /// The endpoint the gateway reports.
    mapped: Option<MappedEndpoint>,
}

impl ExternalAddress {
    /// Takes the endpoint the votes confirmed.
    pub(crate) const fn on_vote(&mut self, address: SocketAddrV4) {
        self.voted = Some(address);
    }

    /// Takes the gateway's latest report, or its loss.
    pub(crate) const fn on_mapping(&mut self, mapped: Option<MappedEndpoint>) {
        self.mapped = mapped;
    }

    /// The endpoint to advertise, when either source knows the address.
    pub(crate) fn advertised(&self) -> Option<AdvertisedEndpoint> {
        let mapped = self
            .mapped
            .as_ref()
            .filter(|mapped| Self::is_public(mapped.ip));
        let ip = self
            .voted
            .map(|voted| *voted.ip())
            .or_else(|| mapped.map(|m| m.ip))?;
        // The gateway's ports hold only on the gateway's own address.
        let mapped = mapped.filter(|mapped| mapped.ip == ip);
        Some(AdvertisedEndpoint {
            ip,
            udp: self
                .voted
                .map(|voted| voted.port())
                .or_else(|| mapped.and_then(|m| m.udp)),
            tcp: mapped.and_then(|m| m.tcp),
            quic: mapped.and_then(|m| m.quic),
        })
    }

    /// Whether peers on the internet can reach an address.
    ///
    /// Private, shared, loopback, link-local, documentation, and reserved ranges cannot.
    /// See RFC 6890 for the special-purpose registry these come from.
    const fn is_public(ip: Ipv4Addr) -> bool {
        let [a, b, c, _] = ip.octets();
        // 100.64.0.0/10 is the carrier-grade NAT range, per RFC 6598.
        let shared = a == 100 && b & 0xc0 == 64;
        // 192.0.0.0/24 holds protocol assignments; 198.18.0.0/15 is for benchmarking.
        let protocol = a == 192 && b == 0 && c == 0;
        let benchmarking = a == 198 && b & 0xfe == 18;
        !(ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_multicast()
            || ip.is_documentation()
            || shared
            || protocol
            || benchmarking
            || a >= 240)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public address outside every documentation range, so the public check passes.
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(81, 2, 3, 4);

    /// The gateway forwarding TCP 9000, UDP 9001, and QUIC 9002 on an external address.
    fn mapped(ip: Ipv4Addr) -> MappedEndpoint {
        MappedEndpoint {
            ip,
            tcp: Some(9000),
            udp: Some(9001),
            quic: Some(9002),
        }
    }

    #[test]
    fn nothing_known_advertises_nothing() {
        assert_eq!(ExternalAddress::default().advertised(), None);
    }

    #[test]
    fn a_public_mapping_alone_gives_every_port() {
        let mut external = ExternalAddress::default();
        external.on_mapping(Some(mapped(PUBLIC)));
        assert_eq!(
            external.advertised(),
            Some(AdvertisedEndpoint {
                ip: PUBLIC,
                udp: Some(9001),
                tcp: Some(9000),
                quic: Some(9002),
            })
        );
        // The gateway loses its mapping: nothing is known any more.
        external.on_mapping(None);
        assert_eq!(external.advertised(), None);
    }

    #[test]
    fn a_mapping_behind_a_second_nat_is_ignored() {
        // The home gateway's external address is in the carrier-grade range 100.64.0.0/10.
        let mut external = ExternalAddress::default();
        external.on_mapping(Some(mapped(Ipv4Addr::new(100, 72, 1, 9))));
        assert_eq!(external.advertised(), None);
        // Peers see the provider's address instead; only the voted endpoint is known.
        let voted = SocketAddrV4::new(PUBLIC, 51000);
        external.on_vote(voted);
        assert_eq!(
            external.advertised(),
            Some(AdvertisedEndpoint {
                ip: PUBLIC,
                udp: Some(51000),
                tcp: None,
                quic: None,
            })
        );
    }

    #[test]
    fn votes_and_an_agreeing_mapping_combine() {
        // Peers saw the discv5 socket at port 9001 of the gateway's address.
        let mut external = ExternalAddress::default();
        external.on_vote(SocketAddrV4::new(PUBLIC, 9001));
        external.on_mapping(Some(mapped(PUBLIC)));
        assert_eq!(
            external.advertised(),
            Some(AdvertisedEndpoint {
                ip: PUBLIC,
                udp: Some(9001),
                tcp: Some(9000),
                quic: Some(9002),
            })
        );
    }

    #[test]
    fn votes_win_over_a_disagreeing_mapping() {
        // The gateway claims one public address, but peers see another.
        let seen = Ipv4Addr::new(81, 9, 9, 9);
        let mut external = ExternalAddress::default();
        external.on_mapping(Some(mapped(PUBLIC)));
        external.on_vote(SocketAddrV4::new(seen, 40000));
        assert_eq!(
            external.advertised(),
            Some(AdvertisedEndpoint {
                ip: seen,
                udp: Some(40000),
                tcp: None,
                quic: None,
            })
        );
    }

    #[test]
    fn records_already_stating_the_endpoint_need_no_change() {
        let endpoint = AdvertisedEndpoint {
            ip: PUBLIC,
            udp: Some(9001),
            tcp: None,
            quic: None,
        };
        let stated = Endpoints {
            ip4: Some(PUBLIC),
            udp4: Some(9001),
            tcp4: Some(9000),
            ..Endpoints::default()
        };
        // An absent port leaves the record's tcp entry alone.
        assert!(endpoint.is_stated_by(&stated));
        // Another udp port, or no address yet, needs a new record.
        assert!(!endpoint.is_stated_by(&Endpoints {
            udp4: Some(9005),
            ..stated
        }));
        assert!(!endpoint.is_stated_by(&Endpoints {
            ip4: None,
            ..stated
        }));
    }

    #[test]
    fn special_ranges_are_not_public() {
        let special = [
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 127, 255, 254),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(192, 0, 0, 8),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        ];
        for ip in special {
            assert!(!ExternalAddress::is_public(ip), "{ip}");
        }
        // Just outside the carrier-grade range, and an ordinary address.
        for ip in [Ipv4Addr::new(100, 128, 0, 1), PUBLIC] {
            assert!(ExternalAddress::is_public(ip), "{ip}");
        }
    }
}
