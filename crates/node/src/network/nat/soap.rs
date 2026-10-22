//! SOAP actions on a UPnP port-forwarding service, and the gateway's replies.
//!
//! The envelope and fault shapes are UPnP Device Architecture 1.1, section 3.2.
//! The actions and their argument order are the WANIPConnection:2 service, section 2.5.

use std::{fmt::Write, net::Ipv4Addr};

use super::{NatError, Transport, xml::Xml};

/// The UPnP error a version 1 gateway returns when it only keeps permanent leases.
///
/// See WANIPConnection:2 Table 2-40, error 725, OnlyPermanentLeasesSupported.
pub(crate) const ONLY_PERMANENT_LEASES: u16 = 725;

/// One action invoked on the forwarding service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SoapAction {
    /// Forwards an external port to a local client, per section 2.5.16.
    AddPortMapping {
        /// The transport forwarded.
        transport: Transport,
        /// The external port.
        external: u16,
        /// The local port.
        internal: u16,
        /// The local address the gateway forwards to.
        client: Ipv4Addr,
        /// A label the gateway shows its operator.
        description: &'static str,
        /// Seconds the lease lasts; zero asks a version 1 gateway for a permanent one.
        lease: u32,
    },
    /// Removes a forwarding, per section 2.5.18.
    DeletePortMapping {
        /// The transport forwarded.
        transport: Transport,
        /// The external port.
        external: u16,
    },
    /// Asks for the external address, per section 2.5.20.
    GetExternalIpAddress,
}

impl SoapAction {
    /// The action name, as the SOAPACTION field and the body name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::AddPortMapping { .. } => "AddPortMapping",
            Self::DeletePortMapping { .. } => "DeletePortMapping",
            Self::GetExternalIpAddress => "GetExternalIPAddress",
        }
    }

    /// The SOAPACTION field value: the quoted service type and action.
    pub(crate) fn header(self, service_type: &str) -> String {
        format!("\"{service_type}#{}\"", self.name())
    }

    /// The request body: a SOAP envelope with the arguments in the order the service lists them.
    pub(crate) fn envelope(self, service_type: &str) -> String {
        let name = self.name();
        let mut body = format!(
            "<?xml version=\"1.0\"?>\r\n\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:{name} xmlns:u=\"{service_type}\">"
        );
        for (argument, value) in self.arguments() {
            // Invariant: every value is a number, an address, or a fixed ASCII label.
            // None holds a character XML would need escaped.
            let _infallible = write!(body, "<{argument}>{value}</{argument}>");
        }
        let _infallible = write!(body, "</u:{name}></s:Body></s:Envelope>\r\n");
        body
    }

    /// The arguments, named and in order.
    fn arguments(self) -> Vec<(&'static str, String)> {
        match self {
            Self::AddPortMapping {
                transport,
                external,
                internal,
                client,
                description,
                lease,
            } => vec![
                // An empty remote host is the wildcard: any peer may connect.
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", external.to_string()),
                ("NewProtocol", transport.upnp_name().to_owned()),
                ("NewInternalPort", internal.to_string()),
                ("NewInternalClient", client.to_string()),
                ("NewEnabled", "1".to_owned()),
                ("NewPortMappingDescription", description.to_owned()),
                ("NewLeaseDuration", lease.to_string()),
            ],
            Self::DeletePortMapping {
                transport,
                external,
            } => vec![
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", external.to_string()),
                ("NewProtocol", transport.upnp_name().to_owned()),
            ],
            Self::GetExternalIpAddress => Vec::new(),
        }
    }

    /// Checks the gateway's reply: success, a UPnP fault, or a bare HTTP error.
    ///
    /// # Errors
    ///
    /// Fails with the fault's UPnP error code, or the HTTP status when no fault is given.
    pub(crate) fn check(self, status: u16, body: &str) -> Result<(), NatError> {
        if status == 200 {
            return Ok(());
        }
        // A fault arrives with status 500 and a UPnPError detail.
        let fault = Xml(body)
            .first("UPnPError")
            .and_then(|error| error.text_of("errorCode"))
            .and_then(|code| code.parse().ok());
        Err(match fault {
            Some(code) => NatError::UpnpFault {
                action: self.name(),
                code,
            },
            None => NatError::HttpStatus {
                action: self.name(),
                status,
            },
        })
    }

    /// Reads the external address from a successful address reply.
    ///
    /// # Errors
    ///
    /// Fails when the reply has no address, or one that is not IPv4.
    pub(crate) fn external_address(body: &str) -> Result<Ipv4Addr, NatError> {
        Xml(body)
            .text_of("NewExternalIPAddress")
            .and_then(|text| text.parse().ok())
            .ok_or(NatError::Missing {
                document: "GetExternalIPAddress reply",
                element: "NewExternalIPAddress",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

    #[test]
    fn add_port_mapping_envelope_lists_arguments_in_order() {
        let action = SoapAction::AddPortMapping {
            transport: Transport::Udp,
            external: 9000,
            internal: 9000,
            client: Ipv4Addr::new(192, 168, 1, 20),
            description: "discv5",
            lease: 3600,
        };
        assert_eq!(
            action.header(IP1),
            "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""
        );
        assert_eq!(
            action.envelope(IP1),
            "<?xml version=\"1.0\"?>\r\n\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
             <NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>9000</NewExternalPort>\
             <NewProtocol>UDP</NewProtocol>\
             <NewInternalPort>9000</NewInternalPort>\
             <NewInternalClient>192.168.1.20</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>discv5</NewPortMappingDescription>\
             <NewLeaseDuration>3600</NewLeaseDuration>\
             </u:AddPortMapping></s:Body></s:Envelope>\r\n"
        );
    }

    #[test]
    fn delete_and_address_envelopes() {
        let delete = SoapAction::DeletePortMapping {
            transport: Transport::Tcp,
            external: 9000,
        };
        let head = "<?xml version=\"1.0\"?>\r\n\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>";
        assert_eq!(
            delete.envelope(IP1),
            format!(
                "{head}<u:DeletePortMapping xmlns:u=\"{IP1}\">\
                 <NewRemoteHost></NewRemoteHost>\
                 <NewExternalPort>9000</NewExternalPort>\
                 <NewProtocol>TCP</NewProtocol>\
                 </u:DeletePortMapping></s:Body></s:Envelope>\r\n"
            )
        );
        assert_eq!(
            SoapAction::GetExternalIpAddress.envelope(IP1),
            format!(
                "{head}<u:GetExternalIPAddress xmlns:u=\"{IP1}\">\
                 </u:GetExternalIPAddress></s:Body></s:Envelope>\r\n"
            )
        );
    }

    #[test]
    fn faults_carry_their_upnp_code() {
        // Error 725 from a version 1 gateway, as the device architecture shapes a fault.
        let fault = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
 s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription>
</UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        let action = SoapAction::GetExternalIpAddress;
        assert!(matches!(
            action.check(500, fault),
            Err(NatError::UpnpFault {
                action: "GetExternalIPAddress",
                code: ONLY_PERMANENT_LEASES,
            })
        ));
        // A 500 without a fault body keeps its status.
        assert!(matches!(
            action.check(500, "oops"),
            Err(NatError::HttpStatus {
                action: "GetExternalIPAddress",
                status: 500,
            })
        ));
        assert!(action.check(200, "").is_ok());
    }

    #[test]
    fn the_external_address_reply_reads() {
        let reply = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>
</u:GetExternalIPAddressResponse></s:Body></s:Envelope>"#;
        assert_eq!(
            SoapAction::external_address(reply).ok(),
            Some(Ipv4Addr::new(203, 0, 113, 7))
        );
        // An empty address, as a gateway without a WAN link reports.
        assert!(matches!(
            SoapAction::external_address("<NewExternalIPAddress></NewExternalIPAddress>"),
            Err(NatError::Missing {
                document: "GetExternalIPAddress reply",
                element: "NewExternalIPAddress",
            })
        ));
    }
}
