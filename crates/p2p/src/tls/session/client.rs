//! The client's handshake: one hello, then the server's flight, then its own.

use axiom_crypto::{p256::PublicKey as CertificateKey, x25519::SecretKey as KeyShareSecret};

use super::context::Context;
use crate::tls::{
    ALPN, CipherSuite, Level, TlsError, TlsOutput, VerifiedPeer,
    extension::ExtensionType,
    key_schedule::{HandshakeSecret, Role, TrafficPair},
    message::{
        CertificateRequest, ECDSA_SECP256R1_SHA256, EncryptedExtensions, Finished, HandshakeType,
        LEGACY_VERSION, Message, NewSessionTicket, ServerHello, TLS13,
    },
};

/// The handshake secrets, once the ServerHello is in.
#[derive(Debug)]
pub(crate) struct HandshakeKeys {
    /// The handshake secret, for the master secret later.
    secret: HandshakeSecret,
    /// The handshake traffic secrets.
    traffic: TrafficPair,
}

/// Where the client stands, and what it holds there.
#[derive(Debug)]
pub(crate) enum ClientState {
    /// The ClientHello is out.
    WaitServerHello(KeyShareSecret),
    /// The handshake keys are installed.
    WaitEncryptedExtensions(HandshakeKeys),
    /// The server's extensions are accepted.
    WaitCertificateRequest(HandshakeKeys),
    /// The server asked for a certificate.
    WaitCertificate(HandshakeKeys),
    /// The server certificate checks out; its key must now sign the transcript.
    WaitCertificateVerify(HandshakeKeys, VerifiedPeer, CertificateKey),
    /// The server is authenticated.
    WaitFinished(HandshakeKeys),
    /// Both Finished messages are exchanged.
    Connected,
    /// The handshake failed.
    Failed,
}

impl ClientState {
    /// Advances by one received message.
    pub(crate) fn handle(self, message: &Message, context: &mut Context) -> Result<Self, TlsError> {
        match (self, message.kind()) {
            (Self::WaitServerHello(secret), HandshakeType::SERVER_HELLO) => {
                Self::server_hello(&secret, message, context).map(Self::WaitEncryptedExtensions)
            }
            (Self::WaitEncryptedExtensions(keys), HandshakeType::ENCRYPTED_EXTENSIONS) => {
                Self::encrypted_extensions(message, context)?;
                Ok(Self::WaitCertificateRequest(keys))
            }
            (Self::WaitCertificateRequest(keys), HandshakeType::CERTIFICATE_REQUEST) => {
                Self::certificate_request(message, context)?;
                Ok(Self::WaitCertificate(keys))
            }
            (Self::WaitCertificate(keys), HandshakeType::CERTIFICATE) => {
                let (peer, key) = context.read_certificate(message)?;
                Ok(Self::WaitCertificateVerify(keys, peer, key))
            }
            (Self::WaitCertificateVerify(keys, peer, key), HandshakeType::CERTIFICATE_VERIFY) => {
                context.read_certificate_verify(message, peer, &key)?;
                Ok(Self::WaitFinished(keys))
            }
            (Self::WaitFinished(keys), HandshakeType::FINISHED) => {
                Self::finished(&keys, message, context)?;
                Ok(Self::Connected)
            }
            // RFC 9001, section 4.1.3: a server may send tickets after the handshake; resumption is unused.
            (Self::Connected, HandshakeType::NEW_SESSION_TICKET) => {
                NewSessionTicket::check(message.body())?;
                Ok(Self::Connected)
            }
            (state, _) => Err(message.unexpected(state.waiting_for())),
        }
    }

    /// What the state waits for, for error messages.
    pub(crate) const fn waiting_for(&self) -> &'static str {
        match self {
            Self::WaitServerHello(_) => "waiting for ServerHello",
            Self::WaitEncryptedExtensions(_) => "waiting for EncryptedExtensions",
            Self::WaitCertificateRequest(_) => "waiting for CertificateRequest",
            Self::WaitCertificate(_) => "waiting for the server Certificate",
            Self::WaitCertificateVerify(..) => "waiting for the server CertificateVerify",
            Self::WaitFinished(_) => "waiting for the server Finished",
            Self::Connected => "connected, where only tickets may arrive",
            Self::Failed => "failed",
        }
    }

    /// Accepts the ServerHello, derives the handshake keys, and installs them.
    fn server_hello(
        secret: &KeyShareSecret,
        message: &Message,
        context: &mut Context,
    ) -> Result<HandshakeKeys, TlsError> {
        let hello = ServerHello::parse(message.body())?;
        if hello.legacy_version != LEGACY_VERSION {
            return Err(TlsError::InvalidLegacyVersion(hello.legacy_version));
        }
        // The client sent no session id, so the echo must be empty too.
        if !hello.session_id.is_empty() {
            return Err(TlsError::SessionIdMismatch);
        }
        let suite = CipherSuite::from_code(hello.cipher_suite)
            .filter(|suite| context.suites.contains(suite))
            .ok_or(TlsError::UnofferedCipherSuite(hello.cipher_suite))?;
        hello
            .extensions
            .allow_only(&[ExtensionType::SUPPORTED_VERSIONS, ExtensionType::KEY_SHARE])?;
        if hello.extensions.selected_version()? != TLS13 {
            return Err(TlsError::UnsupportedVersion);
        }
        let (group, share) = hello.extensions.server_key_share()?;
        let shared = Context::agree(secret, group, share)?;

        context.transcript.update(message.raw());
        context.suite = Some(suite);
        let handshake = HandshakeSecret::new(suite, &shared);
        let traffic = handshake.traffic(&context.transcript.hash());
        context.output.push_back(TlsOutput::Keys {
            level: Level::Handshake,
            secrets: traffic.secrets(Role::Client),
        });
        context.buffer.advance(Level::Handshake)?;
        Ok(HandshakeKeys {
            secret: handshake,
            traffic,
        })
    }

    /// Accepts the server's extensions: the libp2p protocol and the transport parameters.
    fn encrypted_extensions(message: &Message, context: &mut Context) -> Result<(), TlsError> {
        let extensions = EncryptedExtensions::parse(message.body())?.extensions;
        // A server may send its groups here; nothing else was offered.
        extensions.allow_only(&[
            ExtensionType::ALPN,
            ExtensionType::QUIC_TRANSPORT_PARAMETERS,
            ExtensionType::SUPPORTED_GROUPS,
        ])?;
        // RFC 7301, section 3.1: the server names exactly one protocol, among those offered.
        match extensions.alpn()?.as_deref() {
            Some([protocol]) if *protocol == ALPN => {}
            Some(_) => return Err(TlsError::UnofferedApplicationProtocol),
            None => return Err(TlsError::NoApplicationProtocol),
        }
        let parameters = extensions.require(ExtensionType::QUIC_TRANSPORT_PARAMETERS)?;
        context.peer_transport_parameters = Some(parameters.to_vec());
        context.transcript.update(message.raw());
        Ok(())
    }

    /// Accepts the request for this side's certificate, which libp2p servers must send.
    fn certificate_request(message: &Message, context: &mut Context) -> Result<(), TlsError> {
        let request = CertificateRequest::parse(message.body())?;
        if !request.context.is_empty() {
            return Err(TlsError::NonEmptyRequestContext(request.context.len()));
        }
        let schemes =
            request
                .extensions
                .signature_algorithms()?
                .ok_or(TlsError::MissingExtension(
                    ExtensionType::SIGNATURE_ALGORITHMS.0,
                ))?;
        if !schemes.contains(&ECDSA_SECP256R1_SHA256) {
            return Err(TlsError::NoCommonSignatureScheme);
        }
        context.transcript.update(message.raw());
        Ok(())
    }

    /// Checks the server Finished, then sends this side's flight and installs the 1-RTT keys.
    fn finished(
        keys: &HandshakeKeys,
        message: &Message,
        context: &mut Context,
    ) -> Result<(), TlsError> {
        let finished = Finished::parse(message.body())?;
        let hash = context.transcript.hash();
        if !keys
            .traffic
            .receiving(Role::Client)
            .verify_finished(&hash, &finished.verify_data)
        {
            return Err(TlsError::InvalidFinished);
        }
        context.transcript.update(message.raw());

        // The application secrets bind the transcript through the server Finished.
        let application = keys.secret.master().traffic(&context.transcript.hash());

        // Certificate, CertificateVerify, then Finished over everything before it.
        let mut flight = context.write_authentication();
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
        context.buffer.advance(Level::Application)
    }
}
