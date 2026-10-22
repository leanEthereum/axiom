//! A live set of forwardings on one gateway, under whichever protocol it speaks.

use std::{net::SocketAddr, time::Duration};

use tracing::{debug, info};

use super::{
    Forwarding, Listener, MappedEndpoint, MappingProtocol, NatError, NatMetrics,
    control::ControlSocket, pmp_session::PmpSession, upnp_session::UpnpSession,
};

/// Seconds a NAT-PMP mapping is asked to live.
///
/// RFC 6886 section 3.3 recommends two hours.
pub(crate) const REQUESTED_LIFETIME: u32 = 7200;

/// Seconds a UPnP lease is asked to last.
///
/// WANIPConnection:2 section 2.5.16 recommends at most one hour.
pub(crate) const UPNP_LEASE: u32 = 3600;

/// Requests sent to delete a mapping before giving up.
///
/// RFC 6886 section 3.1 allows a deletion to be tried only once or twice.
pub(crate) const DELETE_ATTEMPTS: u32 = 2;

/// Where the gateway's servers are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GatewayTargets {
    /// The NAT-PMP server: port 5351 of the default gateway, when one is known.
    pub(crate) port_control: Option<SocketAddr>,
    /// Where SSDP searches go: the multicast group outside tests.
    pub(crate) ssdp: SocketAddr,
    /// How long SSDP answers are collected.
    pub(crate) ssdp_wait: Duration,
}

/// The forwardings one gateway keeps for the node.
#[derive(Debug)]
pub(crate) enum Session {
    /// Over NAT-PMP.
    Pmp(PmpSession),
    /// Over UPnP IGD.
    Upnp(UpnpSession),
}

impl Session {
    /// Asks the gateway for every forwarding: NAT-PMP on the default gateway, then UPnP.
    ///
    /// # Errors
    ///
    /// Fails with the last protocol's error when none grants a forwarding.
    pub(crate) async fn establish(
        targets: GatewayTargets,
        listeners: &[(Listener, u16)],
        metrics: &NatMetrics,
    ) -> Result<Self, NatError> {
        // Phase 1: NAT-PMP, which needs the default gateway's address.
        if let Some(server) = targets.port_control {
            let socket = ControlSocket::connect(server).await?;
            match PmpSession::establish(socket, listeners.to_vec()).await {
                Ok(session) => return Ok(Self::Pmp(session)),
                Err(error) => {
                    metrics.failed(MappingProtocol::NatPmp);
                    debug!(%error, "NAT-PMP mapping failed");
                }
            }
        }

        // Phase 2: UPnP, which many home gateways speak instead.
        match UpnpSession::discover(targets.ssdp, targets.ssdp_wait, listeners.to_vec()).await {
            Ok(session) => Ok(Self::Upnp(session)),
            Err(error) => {
                metrics.failed(MappingProtocol::Upnp);
                Err(error)
            }
        }
    }

    /// The protocol in use.
    pub(crate) const fn protocol(&self) -> MappingProtocol {
        match self {
            Self::Pmp(_) => MappingProtocol::NatPmp,
            Self::Upnp(_) => MappingProtocol::Upnp,
        }
    }

    /// The external address and the ports granted.
    pub(crate) fn endpoint(&self) -> MappedEndpoint {
        match self {
            Self::Pmp(session) => session.endpoint(),
            Self::Upnp(session) => session.endpoint(),
        }
    }

    /// How long until the forwardings need renewing: half the shortest lifetime.
    ///
    /// RFC 6886 section 3.3 renews halfway to expiry, like DHCP.
    /// A permanent UPnP lease is renewed on the usual lease schedule, to survive a gateway reboot.
    pub(crate) fn renew_after(&self) -> Duration {
        let granted = match self {
            Self::Pmp(session) => session.granted(),
            Self::Upnp(session) => session.granted(),
        };
        let shortest = granted
            .iter()
            .map(Forwarding::schedule_lifetime)
            .min()
            .unwrap_or(UPNP_LEASE);
        Duration::from_secs(u64::from(shortest / 2))
    }

    /// Renews every forwarding.
    ///
    /// # Errors
    ///
    /// Fails when the gateway stops answering, or grants nothing.
    pub(crate) async fn renew(&mut self) -> Result<(), NatError> {
        match self {
            Self::Pmp(session) => session.renew().await,
            Self::Upnp(session) => session.renew().await,
        }
    }

    /// Deletes every forwarding.
    pub(crate) async fn release(self) {
        let protocol = self.protocol();
        match self {
            Self::Pmp(session) => session.release().await,
            Self::Upnp(session) => session.release().await,
        }
        info!(%protocol, "port mappings released");
    }
}
