//! SSDP search for UPnP gateways: the M-SEARCH request and the answers to it.
//!
//! See UPnP Device Architecture 1.1, section 1.3, "Search".

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// The SSDP multicast group and port, per UPnP Device Architecture section 1.3.2.
pub(crate) const SSDP_GROUP: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));

/// The services that forward ports, most capable first.
///
/// WANIPConnection version 2 is the IGD 2.0 service; version 1 and the PPP service are IGD 1.0.
pub(crate) const SERVICE_TYPES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// Seconds a device may wait before answering, which spreads the answers out.
///
/// UPnP Device Architecture section 1.3.2 allows 1 to 5.
const MAX_WAIT: u8 = 2;

/// An M-SEARCH request for one search target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SearchRequest<'a> {
    /// The service type searched for.
    pub(crate) target: &'a str,
}

impl SearchRequest<'_> {
    /// The request as one UDP datagram.
    pub(crate) fn encode(self) -> Vec<u8> {
        format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: {MAX_WAIT}\r\n\
             ST: {}\r\n\
             \r\n",
            self.target
        )
        .into_bytes()
    }
}

/// A device's answer to a search: where its description lives, and what it offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SearchResponse {
    /// The URL of the device description.
    pub(crate) location: String,
    /// The search target the device matched.
    pub(crate) target: String,
}

impl SearchResponse {
    /// Reads an answer: a 200 status line, then LOCATION and ST fields in any case.
    ///
    /// Anything else, such as another device's announcement, reads as nothing.
    pub(crate) fn parse(datagram: &[u8]) -> Option<Self> {
        let text = str::from_utf8(datagram).ok()?;
        let mut lines = text.split("\r\n");
        let status = lines.next()?;
        let mut parts = status.split_ascii_whitespace();
        if !parts.next()?.starts_with("HTTP/1.") || parts.next()? != "200" {
            return None;
        }
        let mut location = None;
        let mut target = None;
        for line in lines.take_while(|line| !line.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim().to_owned();
            if name.trim().eq_ignore_ascii_case("location") {
                location = Some(value);
            } else if name.trim().eq_ignore_ascii_case("st") {
                target = Some(value);
            }
        }
        Some(Self {
            location: location?,
            target: target?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_request_matches_the_architecture_layout() {
        let request = SearchRequest {
            target: SERVICE_TYPES[1],
        };
        assert_eq!(
            request.encode(),
            b"M-SEARCH * HTTP/1.1\r\n\
              HOST: 239.255.255.250:1900\r\n\
              MAN: \"ssdp:discover\"\r\n\
              MX: 2\r\n\
              ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
              \r\n"
        );
    }

    #[test]
    fn search_response_reads_location_and_target() {
        // A typical home gateway answer, with fields in mixed case.
        let datagram = b"HTTP/1.1 200 OK\r\n\
            CACHE-CONTROL: max-age=120\r\n\
            Location: http://192.168.1.1:5000/rootDesc.xml\r\n\
            SERVER: Linux UPnP/1.1 Gateway/2.3\r\n\
            st: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
            USN: uuid:0001::urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
            EXT:\r\n\
            \r\n";
        assert_eq!(
            SearchResponse::parse(datagram),
            Some(SearchResponse {
                location: "http://192.168.1.1:5000/rootDesc.xml".to_owned(),
                target: "urn:schemas-upnp-org:service:WANIPConnection:1".to_owned(),
            })
        );
    }

    #[test]
    fn other_datagrams_read_as_nothing() {
        // An announcement, a refusal, an answer without a location, and binary noise.
        let notify = b"NOTIFY * HTTP/1.1\r\nLOCATION: http://x/\r\nNT: upnp:rootdevice\r\n\r\n";
        let refused = b"HTTP/1.1 404 Not Found\r\nLOCATION: http://x/\r\nST: a\r\n\r\n";
        let partial = b"HTTP/1.1 200 OK\r\nST: a\r\n\r\n";
        for datagram in [&notify[..], &refused[..], &partial[..], &[0xff, 0xfe][..]] {
            assert_eq!(SearchResponse::parse(datagram), None);
        }
    }
}
