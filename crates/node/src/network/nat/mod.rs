//! NAT traversal: port mapping on the home gateway, and the external address for the record.
//!
//! # Overview
//!
//! A node behind a NAT is reachable only if peers learn an address the NAT forwards.
//! Two sources tell the node that address:
//!
//! - The gateway, when port mapping is on: PCP, then NAT-PMP, then UPnP IGD.
//! - Peers, through discv5: each PONG names the endpoint its sender saw.
//!
//! The record then states the confirmed address and the forwarded ports.
//! An address the operator configured always wins, and is never replaced.
//!
//! The pure codecs live apart from the tokio driver:
//!
//! - Pure: the NAT-PMP and PCP messages, epochs, routes, XML, SSDP, SOAP, descriptions.
//! - Effects: the control socket, the three sessions, and the mapper task.

mod control;
mod description;
mod epoch;
mod error;
mod external;
#[cfg(test)]
mod fake;
mod mapper;
mod metrics;
mod pcp;
mod pcp_session;
mod pmp;
mod pmp_session;
mod port;
mod route;
mod session;
mod soap;
mod ssdp;
mod upnp_session;
mod xml;

use std::{fmt, net::SocketAddrV4};

pub(crate) use self::{
    error::{CodecError, NatError},
    external::{AdvertisedEndpoint, ExternalAddress},
    mapper::PortMapper,
    metrics::NatMetrics,
    port::{Forwarding, ListenPorts, Listener, MappedEndpoint, Transport},
};

/// Whether the node asks its gateway to forward its ports.
///
/// Off by default: a gateway mapping opens the home network, so the operator opts in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortMappingSettings {
    /// Asks the gateway over PCP, NAT-PMP, or UPnP.
    pub enabled: bool,
}

/// The protocol a gateway speaks for port mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum MappingProtocol {
    /// The Port Control Protocol, RFC 6887.
    Pcp,
    /// The NAT Port Mapping Protocol, RFC 6886.
    NatPmp,
    /// UPnP Internet Gateway Device.
    Upnp,
}

impl MappingProtocol {
    /// The metric label.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Pcp => "pcp",
            Self::NatPmp => "nat_pmp",
            Self::Upnp => "upnp",
        }
    }
}

impl fmt::Display for MappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pcp => "PCP",
            Self::NatPmp => "NAT-PMP",
            Self::Upnp => "UPnP",
        })
    }
}

/// The node's view of its external endpoint, and the port mapper feeding it.
#[derive(Debug)]
pub(crate) struct NatTraversal {
    /// The two sources, combined.
    external: ExternalAddress,
    /// The running port mapper, when enabled.
    mapper: Option<PortMapper>,
    /// The metrics it updates.
    metrics: NatMetrics,
    /// Whether the operator fixed the record's address.
    pinned: bool,
}

impl NatTraversal {
    /// Nothing known yet, no mapper, and metrics nothing exports.
    ///
    /// A pinned record keeps the operator's address whatever the sources say.
    pub(crate) fn new(pinned: bool) -> Self {
        Self {
            external: ExternalAddress::default(),
            mapper: None,
            metrics: NatMetrics::detached(),
            pinned,
        }
    }

    /// Exports the metrics, and starts the port mapper when the operator enabled it.
    pub(crate) fn start(
        &mut self,
        settings: PortMappingSettings,
        ports: ListenPorts,
        metrics: NatMetrics,
    ) {
        self.metrics = metrics;
        self.metrics.set_address_known(self.pinned);
        if settings.enabled && !ports.listeners().is_empty() {
            self.mapper = Some(PortMapper::spawn(ports, self.metrics.clone()));
        }
    }

    /// Takes the endpoint peers' votes confirmed.
    pub(crate) fn on_vote(&mut self, address: SocketAddrV4, votes: usize) {
        self.external.on_vote(address);
        self.metrics.set_address_votes(votes);
    }

    /// The endpoint the record should state now; nothing when unknown or pinned.
    pub(crate) fn endpoint(&mut self) -> Option<AdvertisedEndpoint> {
        if let Some(mapper) = &self.mapper {
            self.external.on_mapping(mapper.latest());
        }
        let endpoint = self.external.advertised();
        self.metrics
            .set_address_known(self.pinned || endpoint.is_some());
        endpoint.filter(|_| !self.pinned)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn a_pinned_address_is_never_replaced() {
        // The operator set the address; peers then confirm another one.
        let mut pinned = NatTraversal::new(true);
        pinned.on_vote(SocketAddrV4::new(Ipv4Addr::new(81, 2, 3, 4), 9000), 12);
        assert_eq!(pinned.endpoint(), None);
        // Without a pinned address the same vote is advertised.
        let mut free = NatTraversal::new(false);
        assert_eq!(free.endpoint(), None);
        free.on_vote(SocketAddrV4::new(Ipv4Addr::new(81, 2, 3, 4), 9000), 12);
        assert_eq!(
            free.endpoint(),
            Some(AdvertisedEndpoint {
                ip: Ipv4Addr::new(81, 2, 3, 4),
                udp: Some(9000),
                tcp: None,
                quic: None,
            })
        );
    }
}
