//! The UPnP device description: where a gateway's port-forwarding service takes commands.
//!
//! See UPnP Device Architecture 1.1, section 2.3, "Device description".

use axiom_http::Endpoint;

use super::{ssdp::SERVICE_TYPES, xml::Xml};

/// A gateway service that forwards ports, and the URL it takes SOAP actions at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ControlPoint {
    /// The absolute http URL of the service's control endpoint.
    pub(crate) url: String,
    /// The service type, which names the SOAP action namespace.
    pub(crate) service_type: &'static str,
}

impl ControlPoint {
    /// The most capable forwarding service a device description lists.
    ///
    /// # Arguments
    ///
    /// - `document`: the device description XML.
    /// - `location`: the URL it was fetched from, which relative control URLs resolve against.
    pub(crate) fn from_description(document: &str, location: &str) -> Option<Self> {
        let xml = Xml(document);
        // A version 1.0 description may name a base URL; otherwise the location is the base.
        let base = xml
            .text_of("URLBase")
            .filter(|base| !base.is_empty())
            .unwrap_or_else(|| location.to_owned());
        let services: Vec<(String, String)> = xml
            .elements("service")
            .into_iter()
            .filter_map(|service| {
                Some((
                    service.text_of("serviceType")?,
                    service.text_of("controlURL")?,
                ))
            })
            .collect();
        // Preference follows the list of service types, not the order of the document.
        SERVICE_TYPES.iter().find_map(|&service_type| {
            let (_, control) = services.iter().find(|(kind, _)| kind == service_type)?;
            Some(Self {
                url: Self::resolve(&base, control)?,
                service_type,
            })
        })
    }

    /// An absolute URL for a control URL, against a base.
    ///
    /// Gateways give either an absolute URL or a path on the description's server.
    fn resolve(base: &str, control: &str) -> Option<String> {
        if control
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        {
            return Some(control.to_owned());
        }
        let base = Endpoint::parse(base).ok()?;
        let separator = if control.starts_with('/') { "" } else { "/" };
        Some(format!("http://{}{separator}{control}", base.authority()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IGD 1.0 description, trimmed from a common home router, with a PPP and an IP service.
    const IGD1: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Gateway</friendlyName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/ctl/L3F</controlURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANPPPConn1</serviceId>
                <controlURL>/ctl/PPPConn</controlURL>
                <eventSubURL>/evt/PPPConn</eventSubURL>
                <SCPDURL>/WANPPPCn.xml</SCPDURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <controlURL>/ctl/IPConn</controlURL>
                <eventSubURL>/evt/IPConn</eventSubURL>
                <SCPDURL>/WANIPCn.xml</SCPDURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn the_ip_service_wins_over_ppp_and_resolves_against_the_location() {
        assert_eq!(
            ControlPoint::from_description(IGD1, "http://192.168.1.1:5000/rootDesc.xml"),
            Some(ControlPoint {
                url: "http://192.168.1.1:5000/ctl/IPConn".to_owned(),
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:1",
            })
        );
    }

    #[test]
    fn a_base_url_and_version_two_take_precedence() {
        // An IGD 2.0 device with a URLBase and a relative path without a leading slash.
        let document = r"<root><URLBase>http://10.0.0.1:49152</URLBase><device><serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
              <controlURL>/v1</controlURL></service>
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
              <controlURL>upnp/control/WANIPConn2</controlURL></service>
            </serviceList></device></root>";
        assert_eq!(
            ControlPoint::from_description(document, "http://10.0.0.1:1900/igd.xml"),
            Some(ControlPoint {
                url: "http://10.0.0.1:49152/upnp/control/WANIPConn2".to_owned(),
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:2",
            })
        );
    }

    #[test]
    fn an_absolute_control_url_is_kept() {
        let document = r"<root><service>
            <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
            <controlURL>http://192.168.0.1:80/ppp</controlURL></service></root>";
        assert_eq!(
            ControlPoint::from_description(document, "http://192.168.0.1:5431/desc.xml"),
            Some(ControlPoint {
                url: "http://192.168.0.1:80/ppp".to_owned(),
                service_type: "urn:schemas-upnp-org:service:WANPPPConnection:1",
            })
        );
    }

    #[test]
    fn a_device_without_forwarding_has_no_control_point() {
        // A media server lists services, but none that forwards ports.
        let document = r"<root><service>
            <serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType>
            <controlURL>/cd</controlURL></service></root>";
        assert_eq!(
            ControlPoint::from_description(document, "http://192.168.1.5/desc.xml"),
            None
        );
    }
}
