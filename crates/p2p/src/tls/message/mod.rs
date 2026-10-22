//! Handshake messages: their framing, and each message this stack sends or receives.
//!
//! Every handshake message is framed the same way, per RFC 8446, section 4.
//!
//! ```text
//! [ msg_type: u8 ][ length: u24 ][ body ]
//! ```
//!
//! Parsing here checks structure and the fixed legacy fields.
//! What a side accepts in negotiation is decided by the session.

mod certificate;
mod certificate_request;
mod certificate_verify;
mod client_hello;
mod encrypted_extensions;
mod finished;
mod new_session_ticket;
mod server_hello;

pub(crate) use certificate::CertificateMessage;
pub(crate) use certificate_request::CertificateRequest;
pub(crate) use certificate_verify::CertificateVerify;
pub(crate) use client_hello::ClientHello;
pub(crate) use encrypted_extensions::EncryptedExtensions;
pub(crate) use finished::Finished;
pub(crate) use new_session_ticket::NewSessionTicket;
pub(crate) use server_hello::ServerHello;

use super::{
    TlsError,
    codec::{Width, Writer},
};

/// The legacy version field of TLS 1.3 hellos: TLS 1.2, for middlebox compatibility.
pub(crate) const LEGACY_VERSION: u16 = 0x0303;

/// The supported_versions code of TLS 1.3.
pub(crate) const TLS13: u16 = 0x0304;

/// The named group x25519, per RFC 8446, section 4.2.7.
pub(crate) const X25519: u16 = 0x001d;

/// The signature scheme ecdsa_secp256r1_sha256, per RFC 8446, section 4.2.3.
pub(crate) const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// A handshake message type, per RFC 8446, section 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HandshakeType(pub(crate) u8);

impl HandshakeType {
    /// client_hello.
    pub(crate) const CLIENT_HELLO: Self = Self(1);
    /// server_hello, and also hello_retry_request.
    pub(crate) const SERVER_HELLO: Self = Self(2);
    /// new_session_ticket.
    pub(crate) const NEW_SESSION_TICKET: Self = Self(4);
    /// encrypted_extensions.
    pub(crate) const ENCRYPTED_EXTENSIONS: Self = Self(8);
    /// certificate.
    pub(crate) const CERTIFICATE: Self = Self(11);
    /// certificate_request.
    pub(crate) const CERTIFICATE_REQUEST: Self = Self(13);
    /// certificate_verify.
    pub(crate) const CERTIFICATE_VERIFY: Self = Self(15);
    /// finished.
    pub(crate) const FINISHED: Self = Self(20);

    /// A framed message of this type, whose body the closure writes.
    pub(crate) fn frame(self, body: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(self.0);
        writer.vector(Width::U24, body);
        writer.into_bytes()
    }
}

/// One complete handshake message, header included, as the transcript hashes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    /// The header and body.
    raw: Vec<u8>,
}

impl Message {
    /// Bytes of the header: type and 24-bit length.
    pub(crate) const HEADER_LEN: usize = 4;

    /// Wraps a whole framed message; the buffer guarantees the header matches the body.
    pub(crate) const fn from_raw(raw: Vec<u8>) -> Self {
        Self { raw }
    }

    /// The message type.
    pub(crate) fn kind(&self) -> HandshakeType {
        HandshakeType(self.raw[0])
    }

    /// The body after the header.
    pub(crate) fn body(&self) -> &[u8] {
        &self.raw[Self::HEADER_LEN..]
    }

    /// The whole framed message.
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The error for this message arriving while the state waits for something else.
    pub(crate) fn unexpected(&self, state: &'static str) -> TlsError {
        TlsError::UnexpectedMessage {
            found: self.kind().0,
            state,
        }
    }
}
