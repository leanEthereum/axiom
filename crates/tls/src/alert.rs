//! Alert descriptions: the one-byte reason a side gives when it closes or aborts.

use std::fmt;

/// A TLS alert description, per RFC 8446, section 6, and RFC 5246, section 7.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Alert(pub u8);

impl Alert {
    /// close_notify: the sender will send no more data.
    pub const CLOSE_NOTIFY: Self = Self(0);
    /// unexpected_message.
    pub const UNEXPECTED_MESSAGE: Self = Self(10);
    /// bad_record_mac: a record failed authentication.
    pub const BAD_RECORD_MAC: Self = Self(20);
    /// record_overflow.
    pub const RECORD_OVERFLOW: Self = Self(22);
    /// handshake_failure.
    pub const HANDSHAKE_FAILURE: Self = Self(40);
    /// bad_certificate.
    pub const BAD_CERTIFICATE: Self = Self(42);
    /// unsupported_certificate.
    pub const UNSUPPORTED_CERTIFICATE: Self = Self(43);
    /// certificate_expired.
    pub const CERTIFICATE_EXPIRED: Self = Self(45);
    /// certificate_unknown.
    pub const CERTIFICATE_UNKNOWN: Self = Self(46);
    /// illegal_parameter.
    pub const ILLEGAL_PARAMETER: Self = Self(47);
    /// unknown_ca: no path reaches a trusted root.
    pub const UNKNOWN_CA: Self = Self(48);
    /// decode_error.
    pub const DECODE_ERROR: Self = Self(50);
    /// decrypt_error: a signature or Finished check failed.
    pub const DECRYPT_ERROR: Self = Self(51);
    /// protocol_version.
    pub const PROTOCOL_VERSION: Self = Self(70);
    /// internal_error.
    pub const INTERNAL_ERROR: Self = Self(80);
    /// user_canceled.
    pub const USER_CANCELED: Self = Self(90);
    /// no_renegotiation, a TLS 1.2 warning.
    pub const NO_RENEGOTIATION: Self = Self(100);
    /// missing_extension.
    pub const MISSING_EXTENSION: Self = Self(109);
    /// unsupported_extension.
    pub const UNSUPPORTED_EXTENSION: Self = Self(110);
    /// certificate_required.
    pub const CERTIFICATE_REQUIRED: Self = Self(116);
    /// no_application_protocol.
    pub const NO_APPLICATION_PROTOCOL: Self = Self(120);
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "alert {}", self.0)
    }
}

/// A reason a peer's certificate chain is refused, with the alert that reports it.
///
/// The handshake is generic over who checks certificates, so the reason type varies too.
pub trait CertificateRejection: Clone + fmt::Debug + fmt::Display {
    /// The alert sent to the peer.
    fn alert(&self) -> Alert;
}
