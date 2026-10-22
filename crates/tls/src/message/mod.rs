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
mod key_update;
mod new_session_ticket;
mod server_hello;

pub(crate) use certificate::CertificateMessage;
pub(crate) use certificate_request::CertificateRequest;
pub(crate) use certificate_verify::CertificateVerify;
pub(crate) use client_hello::{ClientHello, Offer};
pub(crate) use encrypted_extensions::EncryptedExtensions;
pub(crate) use finished::Finished;
pub(crate) use key_update::KeyUpdate;
pub(crate) use new_session_ticket::NewSessionTicket;
pub(crate) use server_hello::ServerHello;

use super::{
    ProtocolError,
    codec::{Width, Writer},
};

/// The legacy version field of TLS 1.3 hellos, and the version of TLS 1.2.
///
/// TLS 1.3 keeps 0x0303 in the field for middlebox compatibility, per RFC 8446, section 4.1.2.
pub(crate) const TLS12: u16 = 0x0303;

/// The legacy version field of every hello this stack sends or accepts.
pub(crate) const LEGACY_VERSION: u16 = TLS12;

/// The supported_versions code of TLS 1.3.
pub(crate) const TLS13: u16 = 0x0304;

/// A handshake message type, per RFC 8446, section 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HandshakeType(pub(crate) u8);

impl HandshakeType {
    /// hello_request, a TLS 1.2 renegotiation request.
    pub(crate) const HELLO_REQUEST: Self = Self(0);
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
    /// server_key_exchange, TLS 1.2 only.
    pub(crate) const SERVER_KEY_EXCHANGE: Self = Self(12);
    /// certificate_request.
    pub(crate) const CERTIFICATE_REQUEST: Self = Self(13);
    /// server_hello_done, TLS 1.2 only.
    pub(crate) const SERVER_HELLO_DONE: Self = Self(14);
    /// certificate_verify.
    pub(crate) const CERTIFICATE_VERIFY: Self = Self(15);
    /// client_key_exchange, TLS 1.2 only.
    pub(crate) const CLIENT_KEY_EXCHANGE: Self = Self(16);
    /// finished.
    pub(crate) const FINISHED: Self = Self(20);
    /// key_update, TLS 1.3 only.
    pub(crate) const KEY_UPDATE: Self = Self(24);

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
    pub(crate) fn unexpected(&self, state: &'static str) -> ProtocolError {
        ProtocolError::UnexpectedMessage {
            found: self.kind().0,
            state,
        }
    }
}
