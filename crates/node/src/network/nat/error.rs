//! Why a gateway exchange failed.

use std::{io, time::Duration};

use axiom_http::HttpError;
use thiserror::Error;

use super::MappingProtocol;

/// A gateway message that does not decode, or does not answer the request.
///
/// Every byte comes from the local network, so nothing in it is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum CodecError {
    /// The message is shorter than its layout.
    #[error("message of {actual} bytes is shorter than the {expected} its layout needs")]
    Truncated {
        /// Bytes the layout needs.
        expected: usize,
        /// Bytes received.
        actual: usize,
    },
    /// A PCP message length breaks the framing rules.
    ///
    /// See RFC 6887 section 8.3: 24 to 1100 bytes, a multiple of 4.
    #[error("PCP message of {length} bytes is not a multiple of 4 between 24 and 1100")]
    BadLength {
        /// Bytes received.
        length: usize,
    },
    /// The version byte names another protocol.
    #[error("version {actual} where {expected} was expected")]
    WrongVersion {
        /// The version this decoder reads.
        expected: u8,
        /// The version received.
        actual: u8,
    },
    /// The gateway does not speak the version asked, and names the one it does.
    #[error("the gateway does not speak this version; it speaks version {version}")]
    UnsupportedVersion {
        /// The version the gateway speaks.
        version: u8,
    },
    /// The opcode is not the answer to the request sent.
    #[error("opcode {actual} where {expected} was expected")]
    WrongOpcode {
        /// The response opcode the request calls for.
        expected: u8,
        /// The opcode received.
        actual: u8,
    },
    /// The gateway refused the request with a result code.
    #[error("{protocol} gateway refused with result code {code}")]
    Refused {
        /// The protocol that carried the refusal.
        protocol: MappingProtocol,
        /// The result code.
        code: u16,
    },
    /// A PCP response answers another request: its nonce, protocol, or port differ.
    #[error("PCP response for protocol {protocol} port {internal} answers another request")]
    Unmatched {
        /// The internal port the response names.
        internal: u16,
        /// The protocol number the response names.
        protocol: u8,
    },
    /// A PCP address is IPv6, where only IPv4 is mapped.
    #[error("PCP address is not an IPv4-mapped address")]
    NotIpv4,
}

/// Why the port mapper could not reach, ask, or understand a gateway.
#[derive(Debug, Error)]
pub(crate) enum NatError {
    /// A gateway message did not decode.
    #[error("{0}")]
    Codec(#[from] CodecError),
    /// A socket operation failed.
    #[error("{context}: {error}")]
    Io {
        /// What the socket was doing.
        context: &'static str,
        /// The cause.
        #[source]
        error: io::Error,
    },
    /// The gateway never answered.
    #[error("no answer after {attempts} attempts over {waited:?}")]
    Timeout {
        /// Requests sent.
        attempts: u32,
        /// Total time waited.
        waited: Duration,
    },
    /// No UPnP gateway answered the search.
    #[error("no UPnP gateway answered the search")]
    NoUpnpDevice,
    /// An HTTP exchange with the UPnP gateway failed.
    #[error("UPnP HTTP exchange: {0}")]
    Http(#[from] HttpError),
    /// The UPnP gateway answered with an HTTP error and no SOAP fault.
    #[error("UPnP {action} returned HTTP status {status}")]
    HttpStatus {
        /// The action invoked.
        action: &'static str,
        /// The status code.
        status: u16,
    },
    /// The UPnP gateway answered an action with a fault.
    #[error("UPnP {action} failed with error {code}")]
    UpnpFault {
        /// The action invoked.
        action: &'static str,
        /// The UPnP error code.
        code: u16,
    },
    /// A UPnP document lacks an element the exchange needs.
    #[error("UPnP {document} lacks {element}")]
    Missing {
        /// The document read.
        document: &'static str,
        /// The element that was not found or did not parse.
        element: &'static str,
    },
    /// The gateway mapped none of the ports asked for.
    #[error("{protocol} gateway mapped none of the {asked} ports asked for")]
    NothingMapped {
        /// The protocol tried.
        protocol: MappingProtocol,
        /// Ports asked for.
        asked: usize,
    },
}
