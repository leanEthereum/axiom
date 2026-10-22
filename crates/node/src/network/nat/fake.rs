//! Fake gateways on localhost for the driver tests: a PCP or NAT-PMP server, and a UPnP device.
//!
//! Each fake keeps its forwarding table and a log of every request, for tests to assert on.

use std::{
    collections::BTreeMap,
    future::pending,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use axiom_http::{Method, Request, Response, Router, Server, ServerConfig, StatusCode};
use tokio::{net::UdpSocket, task, time};

use super::xml::Xml;

/// The external address every fake gateway reports.
pub(crate) const EXTERNAL_IP: Ipv4Addr = Ipv4Addr::new(81, 2, 3, 4);

/// What a fake port control server saw, one entry per request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ControlRequest {
    /// A PCP request the server refused with its own version 0.
    Unsupported,
    /// A PCP MAP request.
    PcpMap {
        /// The IANA protocol number.
        protocol: u8,
        /// The local port.
        internal: u16,
        /// The external port suggested.
        suggested_port: u16,
        /// The external address suggested.
        suggested_ip: Ipv4Addr,
        /// The lifetime asked for.
        lifetime: u32,
    },
    /// A NAT-PMP external address request.
    PmpAddress,
    /// A NAT-PMP mapping request.
    PmpMap {
        /// The opcode: 1 for UDP, 2 for TCP.
        opcode: u8,
        /// The local port.
        internal: u16,
        /// The external port suggested.
        suggested: u16,
        /// The lifetime asked for.
        lifetime: u32,
    },
}

/// The fake server's state.
#[derive(Debug)]
pub(crate) struct ControlState {
    /// Whether it speaks PCP; otherwise it speaks NAT-PMP only.
    speaks_pcp: bool,
    /// The lifetime it grants.
    lifetime: u32,
    /// The epoch at the last reset.
    epoch_base: u32,
    /// When the epoch last reset.
    reset_at: time::Instant,
    /// Requests until it reboots and forgets its table, if it will.
    reboot_after: Option<usize>,
    /// Live forwardings: protocol number and internal port to external port.
    pub(crate) table: BTreeMap<(u8, u16), u16>,
    /// Every request, in arrival order.
    pub(crate) requests: Vec<ControlRequest>,
}

/// A PCP or NAT-PMP server on a localhost port.
#[derive(Debug)]
pub(crate) struct FakePortControl {
    /// Where it listens.
    pub(crate) addr: SocketAddr,
    /// Its state, shared with its task.
    pub(crate) state: Arc<Mutex<ControlState>>,
}

impl FakePortControl {
    /// Starts a server that grants a lifetime, and reboots after a number of requests if asked.
    pub(crate) async fn start(
        speaks_pcp: bool,
        lifetime: u32,
        reboot_after: Option<usize>,
    ) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = socket.local_addr().expect("address");
        let state = Arc::new(Mutex::new(ControlState {
            speaks_pcp,
            lifetime,
            epoch_base: 1000,
            reset_at: time::Instant::now(),
            reboot_after,
            table: BTreeMap::new(),
            requests: Vec::new(),
        }));
        let shared = Arc::clone(&state);
        task::spawn(async move {
            let mut buffer = [0; 1100];
            while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
                let reply = Self::lock(&shared).answer(&buffer[..length]);
                if let Some(reply) = reply {
                    let _sent = socket.send_to(&reply, from).await;
                }
            }
        });
        Self { addr, state }
    }

    /// The state, for assertions.
    pub(crate) fn state(&self) -> MutexGuard<'_, ControlState> {
        Self::lock(&self.state)
    }

    /// Locks a state, ignoring poisoning: a failed assertion elsewhere must not hide this one.
    fn lock(state: &Mutex<ControlState>) -> MutexGuard<'_, ControlState> {
        state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the server has seen a number of requests, or panics after five seconds.
    pub(crate) async fn wait_for(&self, count: usize) {
        for _ in 0..500 {
            if self.state().requests.len() >= count {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        panic!("saw {:?}", self.state().requests);
    }
}

impl ControlState {
    /// The epoch the server reports now.
    fn epoch(&self) -> u32 {
        self.epoch_base + u32::try_from(self.reset_at.elapsed().as_secs()).unwrap_or(u32::MAX)
    }

    /// Answers one request, then reboots if this was the last before the reboot.
    fn answer(&mut self, request: &[u8]) -> Option<Vec<u8>> {
        let reply = match (request.first()?, self.speaks_pcp) {
            (2, true) => self.pcp_map(request),
            (2, false) => {
                self.requests.push(ControlRequest::Unsupported);
                // A NAT-PMP server names its own version 0 with result 1.
                let mut reply = vec![0, 0x80 | request.get(1)?, 0, 1];
                reply.extend_from_slice(&self.epoch().to_be_bytes());
                Some(reply)
            }
            (0, _) => self.pmp(request),
            _ => None,
        };
        if self.reboot_after == Some(self.requests.len()) {
            self.reboot_after = None;
            self.table.clear();
            self.epoch_base = 0;
            self.reset_at = time::Instant::now();
        }
        reply
    }

    /// Grants or deletes a PCP mapping, on port 10000 above the internal one.
    fn pcp_map(&mut self, request: &[u8]) -> Option<Vec<u8>> {
        let lifetime = u32::from_be_bytes(request.get(4..8)?.try_into().ok()?);
        let protocol = *request.get(36)?;
        let internal = u16::from_be_bytes(request.get(40..42)?.try_into().ok()?);
        let suggested_port = u16::from_be_bytes(request.get(42..44)?.try_into().ok()?);
        let suggested: [u8; 16] = request.get(44..60)?.try_into().ok()?;
        self.requests.push(ControlRequest::PcpMap {
            protocol,
            internal,
            suggested_port,
            suggested_ip: Ipv6Addr::from(suggested).to_ipv4_mapped()?,
            lifetime,
        });
        let (external, granted) = self.update(protocol, internal, lifetime);
        let mut reply = vec![2, 0x81, 0, 0];
        reply.extend_from_slice(&granted.to_be_bytes());
        reply.extend_from_slice(&self.epoch().to_be_bytes());
        reply.extend_from_slice(&[0; 12]);
        reply.extend_from_slice(request.get(24..40)?);
        reply.extend_from_slice(&internal.to_be_bytes());
        reply.extend_from_slice(&external.to_be_bytes());
        reply.extend_from_slice(&EXTERNAL_IP.to_ipv6_mapped().octets());
        Some(reply)
    }

    /// Answers a NAT-PMP address or mapping request.
    fn pmp(&mut self, request: &[u8]) -> Option<Vec<u8>> {
        let opcode = *request.get(1)?;
        let mut reply = vec![0, 0x80 | opcode, 0, 0];
        if opcode == 0 {
            self.requests.push(ControlRequest::PmpAddress);
            reply.extend_from_slice(&self.epoch().to_be_bytes());
            reply.extend_from_slice(&EXTERNAL_IP.octets());
            return Some(reply);
        }
        let internal = u16::from_be_bytes(request.get(4..6)?.try_into().ok()?);
        let suggested = u16::from_be_bytes(request.get(6..8)?.try_into().ok()?);
        let lifetime = u32::from_be_bytes(request.get(8..12)?.try_into().ok()?);
        self.requests.push(ControlRequest::PmpMap {
            opcode,
            internal,
            suggested,
            lifetime,
        });
        // Opcode 1 maps UDP, protocol 17; opcode 2 maps TCP, protocol 6.
        let protocol = if opcode == 1 { 17 } else { 6 };
        let (external, granted) = self.update(protocol, internal, lifetime);
        reply.extend_from_slice(&self.epoch().to_be_bytes());
        reply.extend_from_slice(&internal.to_be_bytes());
        reply.extend_from_slice(&external.to_be_bytes());
        reply.extend_from_slice(&granted.to_be_bytes());
        Some(reply)
    }

    /// Applies a request to the table: the external port and lifetime granted.
    fn update(&mut self, protocol: u8, internal: u16, lifetime: u32) -> (u16, u32) {
        if lifetime == 0 {
            self.table.remove(&(protocol, internal));
            return (0, 0);
        }
        let external = *self
            .table
            .entry((protocol, internal))
            .or_insert(internal + 10000);
        (external, self.lifetime)
    }
}

/// One SOAP action a fake UPnP device received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UpnpCall {
    /// AddPortMapping.
    Add {
        /// TCP or UDP.
        protocol: String,
        /// The external port.
        external: u16,
        /// The local port.
        internal: u16,
        /// The local client address.
        client: String,
        /// The lease asked for.
        lease: u32,
    },
    /// DeletePortMapping.
    Delete {
        /// TCP or UDP.
        protocol: String,
        /// The external port.
        external: u16,
    },
    /// GetExternalIPAddress.
    ExternalAddress,
}

/// The fake device's state.
#[derive(Debug, Default)]
pub(crate) struct UpnpState {
    /// Whether it refuses timed leases with error 725, as some version 1 gateways do.
    permanent_only: bool,
    /// Live forwardings: protocol and external port to lease.
    pub(crate) table: BTreeMap<(String, u16), u32>,
    /// Every action, in arrival order.
    pub(crate) calls: Vec<UpnpCall>,
}

/// A UPnP gateway: an SSDP responder and an HTTP server for its description and control URL.
#[derive(Debug)]
pub(crate) struct FakeUpnp {
    /// Where SSDP searches go.
    pub(crate) ssdp: SocketAddr,
    /// Its state, shared with its tasks.
    pub(crate) state: Arc<Mutex<UpnpState>>,
}

impl FakeUpnp {
    /// The description: an IGD 1.0 gateway with a WANIPConnection:1 service.
    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList>
</device></root>"#;

    /// Starts a device; a permanent-only one refuses timed leases.
    pub(crate) async fn start(permanent_only: bool) -> Self {
        let state = Arc::new(Mutex::new(UpnpState {
            permanent_only,
            ..UpnpState::default()
        }));
        let control = Arc::clone(&state);
        let router = Router::new()
            .route(Method::Get, "/rootDesc.xml", |_| async {
                Response::new(StatusCode::OK)
                    .with_body("text/xml", Self::DESCRIPTION.as_bytes().to_vec())
            })
            .route(Method::Post, "/ctl/IPConn", move |request| {
                let reply = Self::lock(&control).control(&request);
                async move { reply }
            });
        let server = Server::bind((Ipv4Addr::LOCALHOST, 0), router, ServerConfig::default())
            .await
            .expect("bind");
        let http = server.local_addr().expect("address");
        task::spawn(server.serve(pending()));

        // SSDP answers only searches for the IP connection service, as a real IGD 1.0 does.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let ssdp = socket.local_addr().expect("address");
        task::spawn(async move {
            let mut buffer = [0; 2048];
            while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
                let text = String::from_utf8_lossy(&buffer[..length]).into_owned();
                let wanted = "urn:schemas-upnp-org:service:WANIPConnection:1";
                if text.starts_with("M-SEARCH") && text.contains(&format!("ST: {wanted}\r\n")) {
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                         LOCATION: http://{http}/rootDesc.xml\r\nST: {wanted}\r\n\
                         USN: uuid:fake::{wanted}\r\nEXT:\r\n\r\n"
                    );
                    let _sent = socket.send_to(answer.as_bytes(), from).await;
                }
            }
        });
        Self { ssdp, state }
    }

    /// The state, for assertions.
    pub(crate) fn state(&self) -> MutexGuard<'_, UpnpState> {
        Self::lock(&self.state)
    }

    /// Locks a state, ignoring poisoning.
    fn lock(state: &Mutex<UpnpState>) -> MutexGuard<'_, UpnpState> {
        state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the device has seen a number of actions, or panics after five seconds.
    pub(crate) async fn wait_for(&self, count: usize) {
        for _ in 0..500 {
            if self.state().calls.len() >= count {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        panic!("saw {:?}", self.state().calls);
    }
}

impl UpnpState {
    /// Runs one SOAP action.
    fn control(&mut self, request: &Request) -> Response {
        let action = request.headers.get("soapaction").unwrap_or_default();
        let body = String::from_utf8_lossy(&request.body).into_owned();
        let xml = Xml(&body);
        let text = |name| xml.text_of(name).unwrap_or_default();
        let number = |name| -> u16 { text(name).parse().unwrap_or_default() };
        let (call, reply) = if action.ends_with("#AddPortMapping\"") {
            let lease: u32 = text("NewLeaseDuration").parse().unwrap_or_default();
            let call = UpnpCall::Add {
                protocol: text("NewProtocol"),
                external: number("NewExternalPort"),
                internal: number("NewInternalPort"),
                client: text("NewInternalClient"),
                lease,
            };
            if self.permanent_only && lease != 0 {
                (call, Self::fault(725))
            } else {
                self.table
                    .insert((text("NewProtocol"), number("NewExternalPort")), lease);
                (call, Self::ok("<u:AddPortMappingResponse/>"))
            }
        } else if action.ends_with("#DeletePortMapping\"") {
            let key = (text("NewProtocol"), number("NewExternalPort"));
            let found = self.table.remove(&key).is_some();
            let call = UpnpCall::Delete {
                protocol: key.0,
                external: key.1,
            };
            // Error 714, NoSuchEntryInArray, for a forwarding the table lacks.
            let reply = if found {
                Self::ok("<u:DeletePortMappingResponse/>")
            } else {
                Self::fault(714)
            };
            (call, reply)
        } else {
            let reply = Self::ok(&format!(
                "<u:GetExternalIPAddressResponse><NewExternalIPAddress>{EXTERNAL_IP}\
                 </NewExternalIPAddress></u:GetExternalIPAddressResponse>"
            ));
            (UpnpCall::ExternalAddress, reply)
        };
        self.calls.push(call);
        reply
    }

    /// A successful reply around a body element.
    fn ok(inner: &str) -> Response {
        let body = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
             <s:Body>{inner}</s:Body></s:Envelope>"
        );
        Response::new(StatusCode::OK).with_body("text/xml", body.into_bytes())
    }

    /// A SOAP fault with a UPnP error code.
    fn fault(code: u16) -> Response {
        let body = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
             <s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>\
             <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
             <errorCode>{code}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        );
        Response::new(StatusCode::INTERNAL_SERVER_ERROR).with_body("text/xml", body.into_bytes())
    }
}
