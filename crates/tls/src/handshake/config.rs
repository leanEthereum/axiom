//! What each side of a handshake offers and accepts.

use std::sync::Arc;

use crate::{CertifiedKey, CipherSuite, NamedGroup, SignatureScheme, Tls12Suite};

/// The transport a handshake runs over, which fixes a few protocol rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// TLS records over a TCP stream.
    ///
    /// The client sends a session id and a dummy ChangeCipherSpec, per RFC 8446, appendix D.4.
    Tcp,
    /// QUIC CRYPTO frames, per RFC 9001.
    ///
    /// No session id, no ChangeCipherSpec, and no KeyUpdate message; transport parameters are mandatory.
    Quic {
        /// This side's encoded transport parameters.
        parameters: Vec<u8>,
    },
}

impl Transport {
    /// This side's QUIC transport parameters, over QUIC.
    pub(crate) fn quic_parameters(&self) -> Option<&[u8]> {
        match self {
            Self::Tcp => None,
            Self::Quic { parameters } => Some(parameters),
        }
    }
}

/// What a client offers, and what it accepts from the server.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// TLS 1.3 suites, in preference order.
    pub suites: Vec<CipherSuite>,
    /// TLS 1.2 suites, offered after the TLS 1.3 ones; empty means TLS 1.3 only.
    pub tls12_suites: Vec<Tls12Suite>,
    /// Key exchange groups; the client sends a share in each.
    pub groups: Vec<NamedGroup>,
    /// Signature schemes accepted from the server, in preference order.
    pub signature_schemes: Vec<SignatureScheme>,
    /// Application protocols, in preference order.
    pub alpn: Vec<Vec<u8>>,
    /// Whether the server must select an application protocol.
    pub require_alpn: bool,
    /// The DNS name of the server, sent in the server_name extension.
    pub server_name: Option<String>,
    /// The transport.
    pub transport: Transport,
    /// The certificate and key to answer a certificate request with, if any.
    pub identity: Option<Arc<CertifiedKey>>,
}

impl ClientConfig {
    /// The configuration of an HTTPS client, as public servers expect it.
    ///
    /// It offers TLS 1.3 and TLS 1.2, X25519 and P-256, and the ALPN protocol http/1.1.
    #[must_use]
    pub fn https(server_name: Option<String>) -> Self {
        Self {
            suites: CipherSuite::ALL.to_vec(),
            tls12_suites: Tls12Suite::ALL.to_vec(),
            groups: NamedGroup::ALL.to_vec(),
            signature_schemes: SignatureScheme::WEB.to_vec(),
            alpn: vec![b"http/1.1".to_vec()],
            require_alpn: false,
            server_name,
            transport: Transport::Tcp,
            identity: None,
        }
    }
}

/// What a server accepts, and the identity it proves.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// TLS 1.3 suites, in preference order; the first the client offers wins.
    pub suites: Vec<CipherSuite>,
    /// Key exchange groups, in preference order.
    pub groups: Vec<NamedGroup>,
    /// The certificate chain and key.
    pub identity: Arc<CertifiedKey>,
    /// Application protocols, in preference order.
    pub alpn: Vec<Vec<u8>>,
    /// Whether the client must offer one of the protocols.
    pub require_alpn: bool,
    /// Schemes accepted for a client certificate; when set, the server requires one.
    pub client_auth: Option<Vec<SignatureScheme>>,
    /// The transport.
    pub transport: Transport,
}

impl ServerConfig {
    /// The configuration of an HTTPS server: TLS 1.3, no client certificate, http/1.1.
    #[must_use]
    pub fn https(identity: Arc<CertifiedKey>) -> Self {
        Self {
            suites: CipherSuite::ALL.to_vec(),
            groups: NamedGroup::ALL.to_vec(),
            identity,
            alpn: vec![b"http/1.1".to_vec()],
            require_alpn: false,
            client_auth: None,
            transport: Transport::Tcp,
        }
    }
}
