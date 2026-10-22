//! The server's handshake: the client's hello, its whole flight, then the client's.

use axiom_crypto::{p256::PublicKey as CertificateKey, x25519::SecretKey as KeyShareSecret};

use super::context::Context;
use crate::tls::{
    ALPN, CipherSuite, Level, TlsError, TlsOutput, VerifiedPeer,
    extension::ExtensionType,
    key_schedule::{HandshakeSecret, Role, TrafficPair},
    message::{
        CertificateRequest, ClientHello, ECDSA_SECP256R1_SHA256, EncryptedExtensions, Finished,
        HandshakeType, LEGACY_VERSION, Message, ServerHello, TLS13, X25519,
    },
};

/// Where the server stands, and what it holds there.
#[derive(Debug)]
pub(crate) enum ServerState {
    /// Nothing received yet.
    WaitClientHello(KeyShareSecret),
    /// The server flight is out; the client must present its certificate.
    WaitCertificate(TrafficPair),
    /// The client certificate checks out; its key must now sign the transcript.
    WaitCertificateVerify(TrafficPair, VerifiedPeer, CertificateKey),
    /// The client is authenticated.
    WaitFinished(TrafficPair),
    /// Both Finished messages are exchanged.
    Connected,
    /// The handshake failed.
    Failed,
}

impl ServerState {
    /// Advances by one received message.
    pub(crate) fn handle(self, message: &Message, context: &mut Context) -> Result<Self, TlsError> {
        match (self, message.kind()) {
            (Self::WaitClientHello(secret), HandshakeType::CLIENT_HELLO) => {
                Self::client_hello(&secret, message, context).map(Self::WaitCertificate)
            }
            (Self::WaitCertificate(traffic), HandshakeType::CERTIFICATE) => {
                let (peer, key) = context.read_certificate(message)?;
                Ok(Self::WaitCertificateVerify(traffic, peer, key))
            }
            (
                Self::WaitCertificateVerify(traffic, peer, key),
                HandshakeType::CERTIFICATE_VERIFY,
            ) => {
                context.read_certificate_verify(message, peer, &key)?;
                Ok(Self::WaitFinished(traffic))
            }
            (Self::WaitFinished(traffic), HandshakeType::FINISHED) => {
                let finished = Finished::parse(message.body())?;
                let hash = context.transcript.hash();
                if !traffic
                    .receiving(Role::Server)
                    .verify_finished(&hash, &finished.verify_data)
                {
                    return Err(TlsError::InvalidFinished);
                }
                context.transcript.update(message.raw());
                context.buffer.advance(Level::Application)?;
                Ok(Self::Connected)
            }
            (state, _) => Err(message.unexpected(state.waiting_for())),
        }
    }

    /// What the state waits for, for error messages.
    pub(crate) const fn waiting_for(&self) -> &'static str {
        match self {
            Self::WaitClientHello(_) => "waiting for ClientHello",
            Self::WaitCertificate(_) => "waiting for the client Certificate",
            Self::WaitCertificateVerify(..) => "waiting for the client CertificateVerify",
            Self::WaitFinished(_) => "waiting for the client Finished",
            Self::Connected => "connected, where clients send no handshake message",
            Self::Failed => "failed",
        }
    }

    /// Negotiates from the ClientHello, then sends the whole server flight.
    ///
    /// # Returns
    ///
    /// The handshake traffic secrets, which check the client's Finished.
    fn client_hello(
        secret: &KeyShareSecret,
        message: &Message,
        context: &mut Context,
    ) -> Result<TrafficPair, TlsError> {
        let hello = ClientHello::parse(message.body())?;
        let (suite, shared) = Self::negotiate(&hello, secret, context)?;
        context.transcript.update(message.raw());
        context.suite = Some(suite);

        // Phase 1: the ServerHello at the Initial level, then the handshake keys.
        let public = secret.public_key().to_bytes();
        let server_hello = context.send(ServerHello::encode(&context.random, suite, &public));
        context.emit(Level::Initial, server_hello);
        let handshake = HandshakeSecret::new(suite, &shared);
        let traffic = handshake.traffic(&context.transcript.hash());
        context.output.push_back(TlsOutput::Keys {
            level: Level::Handshake,
            secrets: traffic.secrets(Role::Server),
        });

        // Phase 2: the encrypted flight, ending with Finished over all of it.
        let mut flight = context.send(EncryptedExtensions::encode(
            &context.transport_parameters.clone(),
        ));
        flight.extend(context.send(CertificateRequest::encode()));
        flight.extend(context.write_authentication());
        let verify_data = traffic
            .sending(Role::Server)
            .finished(&context.transcript.hash());
        flight.extend(context.send(Finished::encode(&verify_data)));
        context.emit(Level::Handshake, flight);

        // Phase 3: the application keys, bound to the transcript through the server Finished.
        let application = handshake.master().traffic(&context.transcript.hash());
        context.output.push_back(TlsOutput::Keys {
            level: Level::Application,
            secrets: application.secrets(Role::Server),
        });
        context.buffer.advance(Level::Handshake)?;
        Ok(traffic)
    }

    /// Checks the ClientHello against this stack's profile and picks the suite and share.
    ///
    /// Every check names the rule it enforces:
    ///
    /// - TLS 1.3 only, through supported_versions, per RFC 8446, section 4.2.1;
    /// - no session id, per RFC 9001, section 8.4;
    /// - ECDSA P-256 signatures, the only scheme this stack verifies;
    /// - an X25519 share, since a hello retry is not supported;
    /// - the libp2p protocol, per RFC 9001, section 8.1;
    /// - transport parameters, per RFC 9001, section 8.2.
    fn negotiate(
        hello: &ClientHello<'_>,
        secret: &KeyShareSecret,
        context: &mut Context,
    ) -> Result<(CipherSuite, [u8; 32]), TlsError> {
        if hello.legacy_version != LEGACY_VERSION {
            return Err(TlsError::InvalidLegacyVersion(hello.legacy_version));
        }
        if !hello.session_id.is_empty() {
            return Err(TlsError::NonEmptySessionId(hello.session_id.len()));
        }
        let extensions = &hello.extensions;
        if !extensions
            .supported_versions()?
            .is_some_and(|versions| versions.contains(&TLS13))
        {
            return Err(TlsError::UnsupportedVersion);
        }
        let suite = context
            .suites
            .iter()
            .copied()
            .find(|suite| hello.cipher_suites.contains(&suite.code()))
            .ok_or(TlsError::NoCommonCipherSuite)?;
        let schemes = extensions
            .signature_algorithms()?
            .ok_or(TlsError::MissingExtension(
                ExtensionType::SIGNATURE_ALGORITHMS.0,
            ))?;
        if !schemes.contains(&ECDSA_SECP256R1_SHA256) {
            return Err(TlsError::NoCommonSignatureScheme);
        }

        // RFC 8446, section 9.2: a key share comes with the supported groups.
        let shares = extensions
            .client_key_shares()?
            .ok_or(TlsError::MissingExtension(ExtensionType::KEY_SHARE.0))?;
        extensions
            .supported_groups()?
            .ok_or(TlsError::MissingExtension(
                ExtensionType::SUPPORTED_GROUPS.0,
            ))?;
        let &(group, share) = shares
            .iter()
            .find(|(group, _)| *group == X25519)
            .ok_or(TlsError::NoKeyShare)?;
        let shared = Context::agree(secret, group, share)?;

        if !extensions
            .alpn()?
            .is_some_and(|protocols| protocols.contains(&ALPN))
        {
            return Err(TlsError::NoApplicationProtocol);
        }
        let parameters = extensions.require(ExtensionType::QUIC_TRANSPORT_PARAMETERS)?;
        context.peer_transport_parameters = Some(parameters.to_vec());
        Ok((suite, shared))
    }
}
