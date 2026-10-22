//! The client's handshake: one hello, then the server's flight, then its own.

use std::mem;

use super::{ClientConfig, context::Context};
use crate::{
    CipherSuite, Level, NamedGroup, ProtocolError, SignatureScheme, TlsError, TlsOutput, Verifier,
    extension::ExtensionType,
    group::KeyShareSecret,
    key_schedule::{HandshakeSecret, Role, TrafficPair},
    message::{
        CertificateRequest, ClientHello, EncryptedExtensions, Finished, HandshakeType, KeyUpdate,
        LEGACY_VERSION, Message, NewSessionTicket, Offer, ServerHello, TLS12, TLS13,
    },
    tls12::Tls12Client,
    x509::PublicKey,
};

/// The last eight bytes of a TLS 1.2 server random when the server also speaks TLS 1.3.
///
/// RFC 8446, section 4.1.3: "DOWNGRD" then 0x01.
const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";

/// The handshake secrets, once the ServerHello is in.
#[derive(Debug)]
pub(crate) struct HandshakeKeys {
    /// The handshake secret, for the master secret later.
    secret: HandshakeSecret,
    /// The handshake traffic secrets.
    traffic: TrafficPair,
}

/// The schemes a server's certificate request accepts; none when it asked for nothing.
type Request = Option<Vec<SignatureScheme>>;

/// Where the client stands, and what it holds there.
#[derive(Debug)]
enum ClientState<V: Verifier> {
    /// The ClientHello is out, with one secret per offered share.
    WaitServerHello(Vec<KeyShareSecret>),
    /// The handshake keys are installed.
    WaitEncryptedExtensions(HandshakeKeys),
    /// The server's extensions are accepted; a certificate request may come first.
    WaitCertificateOrRequest(HandshakeKeys),
    /// The server asked for a certificate.
    WaitCertificate(HandshakeKeys, Request),
    /// The server certificate checks out; its key must now sign the transcript.
    WaitCertificateVerify(HandshakeKeys, Request, V::Peer, PublicKey),
    /// The server is authenticated.
    WaitFinished(HandshakeKeys, Request),
    /// The server chose TLS 1.2.
    Tls12(Box<Tls12Client<V>>),
    /// The handshake is done, in the version negotiated.
    Connected {
        /// Whether TLS 1.2 was negotiated.
        tls12: bool,
    },
    /// The handshake failed.
    Failed,
}

/// The client side of a handshake.
#[derive(Debug)]
pub(crate) struct Client<V: Verifier> {
    /// What the client offers.
    config: ClientConfig,
    /// The legacy session id sent, which the server must echo.
    session_id: Vec<u8>,
    /// Where the handshake stands.
    state: ClientState<V>,
}

impl<V: Verifier> Client<V> {
    /// Builds and queues the ClientHello.
    pub(crate) fn start(config: ClientConfig, context: &mut Context<V>) -> Self {
        let quic = config.transport.quic_parameters().is_some();
        // RFC 8446, appendix D.4: a TCP client sends a session id; QUIC forbids one.
        let session_id = if quic {
            Vec::new()
        } else {
            context.randomness.session_id.to_vec()
        };
        let secrets: Vec<KeyShareSecret> = config
            .groups
            .iter()
            .filter_map(|&group| {
                let bytes = match group {
                    NamedGroup::SECP256R1 => context.randomness.p256,
                    _ => context.randomness.x25519,
                };
                KeyShareSecret::new(group, bytes)
            })
            .collect();
        let shares: Vec<_> = secrets
            .iter()
            .map(|secret| (secret.group(), secret.public()))
            .collect();
        let tls12 = !quic && !config.tls12_suites.is_empty();
        let suites: Vec<u16> = config
            .suites
            .iter()
            .map(|suite| suite.code())
            .chain(
                config
                    .tls12_suites
                    .iter()
                    .filter(|_| tls12)
                    .map(|suite| suite.code()),
            )
            .collect();
        let versions: &[u16] = if tls12 { &[TLS13, TLS12] } else { &[TLS13] };
        let hello = ClientHello::encode(&Offer {
            random: &context.randomness.random,
            session_id: &session_id,
            suites: &suites,
            versions,
            groups: &config.groups,
            shares: &shares,
            schemes: &config.signature_schemes,
            server_name: config.server_name.as_deref(),
            alpn: &config.alpn,
            quic_parameters: config.transport.quic_parameters(),
            tls12,
        });
        let hello = context.send(hello);
        context.emit(Level::Initial, hello);
        Self {
            config,
            session_id,
            state: ClientState::WaitServerHello(secrets),
        }
    }

    /// Whether the handshake is done.
    pub(crate) const fn is_connected(&self) -> bool {
        matches!(self.state, ClientState::Connected { .. })
    }

    /// Whether TLS 1.2 was negotiated.
    pub(crate) const fn is_tls12(&self) -> bool {
        matches!(
            self.state,
            ClientState::Tls12(_) | ClientState::Connected { tls12: true }
        )
    }

    /// Keeps only the given TLS 1.3 suites as acceptable.
    pub(crate) fn restrict_suites(&mut self, suites: &[CipherSuite]) {
        self.config.suites = suites.to_vec();
    }

    /// Marks the handshake failed.
    pub(crate) fn fail(&mut self) {
        self.state = ClientState::Failed;
    }

    /// Advances by one received message.
    pub(crate) fn handle(
        &mut self,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<(), TlsError<V::Error>> {
        let state = mem::replace(&mut self.state, ClientState::Failed);
        self.state = match (state, message.kind()) {
            (ClientState::WaitServerHello(secrets), HandshakeType::SERVER_HELLO) => {
                self.server_hello(secrets, message, context)?
            }
            (ClientState::WaitEncryptedExtensions(keys), HandshakeType::ENCRYPTED_EXTENSIONS) => {
                self.encrypted_extensions(message, context)?;
                ClientState::WaitCertificateOrRequest(keys)
            }
            (ClientState::WaitCertificateOrRequest(keys), HandshakeType::CERTIFICATE_REQUEST) => {
                let request = Self::certificate_request(message, context)?;
                ClientState::WaitCertificate(keys, Some(request))
            }
            (ClientState::WaitCertificateOrRequest(keys), HandshakeType::CERTIFICATE) => {
                let (peer, key) = context.read_certificate(message)?;
                ClientState::WaitCertificateVerify(keys, None, peer, key)
            }
            (ClientState::WaitCertificate(keys, request), HandshakeType::CERTIFICATE) => {
                let (peer, key) = context.read_certificate(message)?;
                ClientState::WaitCertificateVerify(keys, request, peer, key)
            }
            (
                ClientState::WaitCertificateVerify(keys, request, peer, key),
                HandshakeType::CERTIFICATE_VERIFY,
            ) => {
                context.read_certificate_verify(
                    message,
                    &self.config.signature_schemes,
                    peer,
                    &key,
                )?;
                ClientState::WaitFinished(keys, request)
            }
            (ClientState::WaitFinished(keys, request), HandshakeType::FINISHED) => {
                self.finished(&keys, request.as_deref(), message, context)?;
                ClientState::Connected { tls12: false }
            }
            (ClientState::Tls12(mut client), _) => {
                if client.handle(message, context)? {
                    ClientState::Connected { tls12: true }
                } else {
                    ClientState::Tls12(client)
                }
            }
            // RFC 8446, section 4.6.1: a server may send tickets after the handshake; resumption is unused.
            (ClientState::Connected { tls12: false }, HandshakeType::NEW_SESSION_TICKET) => {
                NewSessionTicket::check(message.body())?;
                ClientState::Connected { tls12: false }
            }
            // RFC 8446, section 4.6.3; QUIC replaces the message with its own key phase, per RFC 9001, section 6.
            (ClientState::Connected { tls12: false }, HandshakeType::KEY_UPDATE)
                if self.config.transport.quic_parameters().is_none() =>
            {
                let update = KeyUpdate::parse(message.body())?;
                context.output.push_back(TlsOutput::PeerKeyUpdate {
                    update_requested: update.update_requested,
                });
                ClientState::Connected { tls12: false }
            }
            // RFC 5246, section 7.4.1.1: a client may ignore a request to renegotiate.
            (ClientState::Connected { tls12: true }, HandshakeType::HELLO_REQUEST)
                if message.body().is_empty() =>
            {
                ClientState::Connected { tls12: true }
            }
            (state, _) => return Err(message.unexpected(state.waiting_for()).into()),
        };
        Ok(())
    }

    /// Accepts the ServerHello, then derives and installs the handshake keys.
    ///
    /// A ServerHello without supported_versions selects TLS 1.2, when offered.
    fn server_hello(
        &self,
        secrets: Vec<KeyShareSecret>,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<ClientState<V>, TlsError<V::Error>> {
        let hello = ServerHello::parse(message.body())?;
        if hello.legacy_version != LEGACY_VERSION {
            return Err(ProtocolError::InvalidLegacyVersion(hello.legacy_version).into());
        }
        if hello
            .extensions
            .get(ExtensionType::SUPPORTED_VERSIONS)
            .is_none()
        {
            if self.config.tls12_suites.is_empty()
                || self.config.transport.quic_parameters().is_some()
            {
                return Err(ProtocolError::UnsupportedVersion.into());
            }
            // RFC 8446, section 4.1.3: a TLS 1.3 server never answers a TLS 1.3 client with 1.2.
            if hello.random[24..] == DOWNGRADE_TLS12 {
                return Err(ProtocolError::Downgrade.into());
            }
            let client = Tls12Client::start(&self.config, &hello, message, secrets, context)?;
            return Ok(ClientState::Tls12(Box::new(client)));
        }

        if hello.session_id != self.session_id {
            return Err(ProtocolError::SessionIdMismatch.into());
        }
        let suite = CipherSuite::from_code(hello.cipher_suite)
            .filter(|suite| self.config.suites.contains(suite))
            .ok_or(ProtocolError::UnofferedCipherSuite(hello.cipher_suite))?;
        hello
            .extensions
            .allow_only(&[ExtensionType::SUPPORTED_VERSIONS, ExtensionType::KEY_SHARE])?;
        if hello.extensions.selected_version()? != TLS13 {
            return Err(ProtocolError::UnsupportedVersion.into());
        }
        let (group, share) = hello.extensions.server_key_share()?;
        let secret = secrets
            .iter()
            .find(|secret| secret.group().0 == group)
            .ok_or(ProtocolError::UnofferedGroup(group))?;
        let mut shared = secret.agree(share)?;

        context.transcript.update(message.raw());
        context.suite = Some(suite);
        let handshake = HandshakeSecret::new(suite, &shared);
        shared.fill(0);
        let traffic = handshake.traffic(&context.transcript.hash());
        context.output.push_back(TlsOutput::Keys {
            level: Level::Handshake,
            secrets: traffic.secrets(Role::Client),
        });
        context.buffer.advance(Level::Handshake)?;
        Ok(ClientState::WaitEncryptedExtensions(HandshakeKeys {
            secret: handshake,
            traffic,
        }))
    }

    /// Accepts the server's extensions: the application protocol, and QUIC parameters.
    fn encrypted_extensions(
        &self,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<(), TlsError<V::Error>> {
        let extensions = EncryptedExtensions::parse(message.body())?.extensions;
        let quic = self.config.transport.quic_parameters().is_some();
        let mut allowed = vec![ExtensionType::ALPN, ExtensionType::SUPPORTED_GROUPS];
        if self.config.server_name.is_some() {
            allowed.push(ExtensionType::SERVER_NAME);
        }
        if quic {
            allowed.push(ExtensionType::QUIC_TRANSPORT_PARAMETERS);
        }
        extensions.allow_only(&allowed)?;
        extensions.require_empty(ExtensionType::SERVER_NAME)?;

        // RFC 7301, section 3.1: the server names exactly one protocol, among those offered.
        match extensions.alpn()?.as_deref() {
            Some([protocol]) if self.config.alpn.iter().any(|offered| offered == protocol) => {
                context.alpn = Some(protocol.to_vec());
            }
            Some(_) => return Err(ProtocolError::UnofferedApplicationProtocol.into()),
            None if self.config.require_alpn => {
                return Err(ProtocolError::NoApplicationProtocol.into());
            }
            None => {}
        }
        if quic {
            let parameters = extensions.require(ExtensionType::QUIC_TRANSPORT_PARAMETERS)?;
            context.peer_transport_parameters = Some(parameters.to_vec());
        }
        context.transcript.update(message.raw());
        Ok(())
    }

    /// Accepts a request for this side's certificate, returning the schemes it accepts.
    fn certificate_request(
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<Vec<SignatureScheme>, TlsError<V::Error>> {
        let request = CertificateRequest::parse(message.body())?;
        if !request.context.is_empty() {
            return Err(ProtocolError::NonEmptyRequestContext(request.context.len()).into());
        }
        let schemes =
            request
                .extensions
                .signature_algorithms()?
                .ok_or(ProtocolError::MissingExtension(
                    ExtensionType::SIGNATURE_ALGORITHMS.0,
                ))?;
        context.transcript.update(message.raw());
        Ok(schemes.into_iter().map(SignatureScheme).collect())
    }

    /// Checks the server Finished, then sends this side's flight and installs the 1-RTT keys.
    fn finished(
        &self,
        keys: &HandshakeKeys,
        request: Option<&[SignatureScheme]>,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<(), TlsError<V::Error>> {
        let finished = Finished::parse(message.body())?;
        let hash = context.transcript.hash();
        if !keys
            .traffic
            .receiving(Role::Client)
            .verify_finished(&hash, &finished.verify_data)
        {
            return Err(ProtocolError::InvalidFinished.into());
        }
        context.transcript.update(message.raw());

        // The application secrets bind the transcript through the server Finished.
        let application = keys.secret.master().traffic(&context.transcript.hash());

        // RFC 8446, appendix D.4: a dummy ChangeCipherSpec precedes the second flight over TCP.
        if !self.session_id.is_empty() {
            context.output.push_back(TlsOutput::ChangeCipherSpec);
        }
        // Certificate and CertificateVerify when asked, then Finished over everything before it.
        let mut flight = match request {
            Some(schemes) => {
                context.write_authentication(self.config.identity.as_ref(), schemes)?
            }
            None => Vec::new(),
        };
        let verify_data = keys
            .traffic
            .sending(Role::Client)
            .finished(&context.transcript.hash());
        flight.extend(context.send(Finished::encode(&verify_data)));
        context.emit(Level::Handshake, flight);
        context.output.push_back(TlsOutput::Keys {
            level: Level::Application,
            secrets: application.secrets(Role::Client),
        });
        context.buffer.advance(Level::Application)?;
        Ok(())
    }
}

impl<V: Verifier> ClientState<V> {
    /// What the state waits for, for error messages.
    const fn waiting_for(&self) -> &'static str {
        match self {
            Self::WaitServerHello(_) => "waiting for ServerHello",
            Self::WaitEncryptedExtensions(_) => "waiting for EncryptedExtensions",
            Self::WaitCertificateOrRequest(_) => "waiting for the server Certificate",
            Self::WaitCertificate(..) => "waiting for the server Certificate after a request",
            Self::WaitCertificateVerify(..) => "waiting for the server CertificateVerify",
            Self::WaitFinished(..) => "waiting for the server Finished",
            Self::Tls12(_) => "running a TLS 1.2 handshake",
            Self::Connected { .. } => "connected, where only tickets and key updates may arrive",
            Self::Failed => "failed",
        }
    }
}
