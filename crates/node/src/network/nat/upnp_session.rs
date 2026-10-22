//! Forwardings kept alive over UPnP IGD: SSDP search, the device description, and SOAP actions.

use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use axiom_http::{Client, ClientConfig, Endpoint, Method, Request};
use tokio::{net::UdpSocket, time};
use tracing::{debug, warn};

use super::{
    Forwarding, Listener, MappedEndpoint, MappingProtocol, NatError,
    description::ControlPoint,
    session::UPNP_LEASE,
    soap::{ONLY_PERMANENT_LEASES, SoapAction},
    ssdp::{SERVICE_TYPES, SearchRequest, SearchResponse},
};

/// The longest wait for one HTTP exchange with the gateway.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest SSDP datagram read.
const MAX_DATAGRAM: usize = 2048;

/// The forwardings one UPnP gateway granted.
#[derive(Debug)]
pub(crate) struct UpnpSession {
    /// The forwarding service.
    control: ControlPoint,
    /// The HTTP client bound to the service's server.
    client: Client,
    /// The path of the control URL.
    path: String,
    /// The local address the gateway forwards to.
    local: Ipv4Addr,
    /// The local ports to forward.
    listeners: Vec<(Listener, u16)>,
    /// The forwardings granted at the last pass.
    granted: Vec<Forwarding>,
    /// The gateway's external address.
    external: Ipv4Addr,
    /// The lease asked for; zero once the gateway proved it keeps only permanent ones.
    lease: u32,
}

impl UpnpSession {
    /// Searches for a gateway and asks it for every forwarding.
    ///
    /// # Arguments
    ///
    /// - `search`: where M-SEARCH goes, the SSDP multicast group outside tests.
    /// - `wait`: how long answers are collected.
    ///
    /// # Errors
    ///
    /// Fails when no gateway answers, or none grants a forwarding.
    pub(crate) async fn discover(
        search: SocketAddr,
        wait: Duration,
        listeners: Vec<(Listener, u16)>,
    ) -> Result<Self, NatError> {
        let mut last = NatError::NoUpnpDevice;
        for location in Self::search(search, wait).await? {
            match Self::establish(&location, listeners.clone()).await {
                Ok(session) => return Ok(session),
                Err(error) => {
                    debug!(%error, %location, "UPnP device unusable");
                    last = error;
                }
            }
        }
        Err(last)
    }

    /// The external address and the ports granted.
    pub(crate) fn endpoint(&self) -> MappedEndpoint {
        MappedEndpoint::new(self.external, &self.granted)
    }

    /// The forwardings granted.
    pub(crate) fn granted(&self) -> &[Forwarding] {
        &self.granted
    }

    /// Adds every forwarding again, which renews the leases, and rereads the address.
    ///
    /// A gateway that rebooted and lost its table gets every forwarding back.
    ///
    /// # Errors
    ///
    /// Fails when the gateway stops answering, or grants nothing.
    pub(crate) async fn renew(&mut self) -> Result<(), NatError> {
        self.map_all().await
    }

    /// Deletes every forwarding.
    ///
    /// Deletion is advisory: a lease left behind expires on its own.
    pub(crate) async fn release(self) {
        for forwarding in &self.granted {
            let action = SoapAction::DeletePortMapping {
                transport: forwarding.listener.transport(),
                external: forwarding.external,
            };
            match self.invoke(action).await {
                Ok(_) => debug!(listener = %forwarding.listener, "UPnP mapping deleted"),
                Err(error) => {
                    debug!(%error, listener = %forwarding.listener, "UPnP deletion failed");
                }
            }
        }
    }

    /// The description URLs of gateways that answer a search for a forwarding service.
    async fn search(target: SocketAddr, wait: Duration) -> Result<Vec<String>, NatError> {
        let io = |context| move |error| NatError::Io { context, error };
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(io("binding the SSDP socket"))?;
        for service_type in SERVICE_TYPES {
            let request = SearchRequest {
                target: service_type,
            };
            socket
                .send_to(&request.encode(), target)
                .await
                .map_err(io("sending the SSDP search"))?;
        }
        // Each device answers within the advertised wait; one gateway may answer every search.
        let deadline = time::Instant::now() + wait;
        let mut seen = BTreeSet::new();
        let mut locations = Vec::new();
        let mut buffer = [0; MAX_DATAGRAM];
        while let Ok(received) = time::timeout_at(deadline, socket.recv_from(&mut buffer)).await {
            let Ok((length, _)) = received else {
                continue;
            };
            let Some(answer) = SearchResponse::parse(&buffer[..length]) else {
                continue;
            };
            if SERVICE_TYPES.contains(&answer.target.as_str())
                && seen.insert(answer.location.clone())
            {
                locations.push(answer.location);
            }
        }
        Ok(locations)
    }

    /// Reads a device description and asks its forwarding service for every forwarding.
    async fn establish(location: &str, listeners: Vec<(Listener, u16)>) -> Result<Self, NatError> {
        // Phase 1: the description names the control URL.
        let described = Endpoint::parse(location)?;
        let path = described.path().to_owned();
        let reply = Client::new(described, Self::http_config())
            .send(&Request::new(Method::Get, &path))
            .await?;
        let document = String::from_utf8_lossy(&reply.body);
        let control =
            ControlPoint::from_description(&document, location).ok_or(NatError::Missing {
                document: "device description",
                element: "a WANIPConnection or WANPPPConnection service",
            })?;

        // Phase 2: the local address that faces the gateway is the one it forwards to.
        let endpoint = Endpoint::parse(&control.url)?;
        let local = Self::local_address(&endpoint).await?;
        let mut session = Self {
            path: endpoint.path().to_owned(),
            client: Client::new(endpoint, Self::http_config()),
            control,
            local,
            listeners,
            granted: Vec::new(),
            external: Ipv4Addr::UNSPECIFIED,
            lease: UPNP_LEASE,
        };
        session.map_all().await?;
        Ok(session)
    }

    /// Adds every forwarding, then reads the external address.
    async fn map_all(&mut self) -> Result<(), NatError> {
        let mut granted = Vec::new();
        for (listener, internal) in self.listeners.clone() {
            // The external port matches the internal one, so peers dial the port the node binds.
            match self.add(listener, internal).await {
                Ok(()) => granted.push(Forwarding {
                    listener,
                    internal,
                    external: internal,
                    lifetime: self.lease,
                }),
                Err(error) => {
                    warn!(%error, listener = %listener, port = internal, "UPnP mapping refused");
                }
            }
        }
        self.granted = granted;
        if self.granted.is_empty() {
            return Err(NatError::NothingMapped {
                protocol: MappingProtocol::Upnp,
                asked: self.listeners.len(),
            });
        }
        let body = self.invoke(SoapAction::GetExternalIpAddress).await?;
        self.external = SoapAction::external_address(&body)?;
        Ok(())
    }

    /// Adds one forwarding, falling back to a permanent lease where only those are kept.
    async fn add(&mut self, listener: Listener, internal: u16) -> Result<(), NatError> {
        let action = |lease| SoapAction::AddPortMapping {
            transport: listener.transport(),
            external: internal,
            internal,
            client: self.local,
            description: listener.name(),
            lease,
        };
        match self.invoke(action(self.lease)).await {
            Err(NatError::UpnpFault {
                code: ONLY_PERMANENT_LEASES,
                ..
            }) if self.lease != 0 => {
                // A version 1 gateway may refuse timed leases, per WANIPConnection error 725.
                // A permanent lease is then the only way; renewals keep re-adding it.
                debug!("UPnP gateway keeps only permanent leases");
                self.lease = 0;
                self.invoke(action(0)).await.map(drop)
            }
            outcome => outcome.map(drop),
        }
    }

    /// Invokes one action, returning the reply body.
    async fn invoke(&self, action: SoapAction) -> Result<String, NatError> {
        let service_type = self.control.service_type;
        let request = Request::new(Method::Post, &self.path)
            .with_header("soapaction", action.header(service_type))
            .with_body(
                "text/xml; charset=\"utf-8\"",
                action.envelope(service_type).into_bytes(),
            );
        let reply = self.client.send(&request).await?;
        let body = String::from_utf8_lossy(&reply.body).into_owned();
        action.check(reply.status.as_u16(), &body)?;
        Ok(body)
    }

    /// The local IPv4 address the route to a gateway leaves from.
    async fn local_address(endpoint: &Endpoint) -> Result<Ipv4Addr, NatError> {
        let io = |context| move |error| NatError::Io { context, error };
        let gateway: Ipv4Addr = endpoint.host().parse().map_err(|_| NatError::Missing {
            document: "control URL",
            element: "an IPv4 host",
        })?;
        // Connecting a UDP socket sends nothing; it only asks the kernel for the route.
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(io("binding the route probe"))?;
        socket
            .connect((gateway, endpoint.port()))
            .await
            .map_err(io("probing the route to the gateway"))?;
        match socket
            .local_addr()
            .map_err(io("reading the local address"))?
        {
            SocketAddr::V4(local) => Ok(*local.ip()),
            SocketAddr::V6(_) => Err(NatError::Missing {
                document: "route to the gateway",
                element: "an IPv4 source address",
            }),
        }
    }

    /// The client settings: a short timeout, since the gateway is on the local link.
    fn http_config() -> ClientConfig {
        ClientConfig {
            connect_timeout: HTTP_TIMEOUT,
            request_timeout: HTTP_TIMEOUT,
            ..ClientConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Builder;

    use super::*;
    use crate::network::nat::fake::{EXTERNAL_IP, FakeUpnp, UpnpCall};

    #[test]
    fn permanent_only_gateways_get_permanent_leases_through_renewal_and_release() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Fixture state: a version 1 gateway that refuses timed leases with error 725.
            let device = FakeUpnp::start(true).await;
            let listeners = vec![(Listener::Libp2pTcp, 9000), (Listener::Discovery, 9001)];
            let add = |protocol: &str, port, lease| UpnpCall::Add {
                protocol: protocol.to_owned(),
                external: port,
                internal: port,
                client: "127.0.0.1".to_owned(),
                lease,
            };

            // Phase 1: one refused timed lease, then permanent ones only.
            let mut session =
                UpnpSession::discover(device.ssdp, Duration::from_millis(300), listeners)
                    .await
                    .expect("gateway found");
            assert_eq!(
                session.endpoint(),
                MappedEndpoint {
                    ip: EXTERNAL_IP,
                    tcp: Some(9000),
                    udp: Some(9001),
                    quic: None,
                }
            );
            // Phase 2: a renewal re-adds both, still permanent.
            session.renew().await.expect("renewed");
            // Phase 3: release deletes both.
            session.release().await;
            assert_eq!(
                device.state().calls,
                [
                    add("TCP", 9000, 3600),
                    add("TCP", 9000, 0),
                    add("UDP", 9001, 0),
                    UpnpCall::ExternalAddress,
                    add("TCP", 9000, 0),
                    add("UDP", 9001, 0),
                    UpnpCall::ExternalAddress,
                    UpnpCall::Delete {
                        protocol: "TCP".to_owned(),
                        external: 9000,
                    },
                    UpnpCall::Delete {
                        protocol: "UDP".to_owned(),
                        external: 9001,
                    },
                ]
            );
            assert!(device.state().table.is_empty());
        });
    }

    #[test]
    fn a_search_nobody_answers_finds_no_gateway() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // A socket that reads nothing stands in for an empty network.
            let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            let found = UpnpSession::discover(
                silent.local_addr().expect("address"),
                Duration::from_millis(100),
                vec![(Listener::Discovery, 9001)],
            )
            .await;
            assert!(matches!(found, Err(NatError::NoUpnpDevice)));
        });
    }
}
