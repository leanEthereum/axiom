//! The server's handshake: the client's hello, its whole flight, then the client's.

use std::mem;

use super::{ServerConfig, context::Context};
use crate::{
    CipherSuite, Level, NamedGroup, ProtocolError, SignatureScheme, TlsError, TlsOutput, Verifier,
    extension::ExtensionType,
    group::KeyShareSecret,
    key_schedule::{HandshakeSecret, Role, TrafficPair},
    message::{
        CertificateRequest, ClientHello, EncryptedExtensions, Finished, HandshakeType, KeyUpdate,
        LEGACY_VERSION, Message, ServerHello, TLS13,
    },
    x509::PublicKey,
};

/// Where the server stands, and what it holds there.
#[derive(Debug)]
enum ServerState<V: Verifier> {
    /// Nothing received yet.
    WaitClientHello,
    /// The server flight is out; the client must present its certificate.
    WaitCertificate(TrafficPair),
    /// The client certificate checks out; its key must now sign the transcript.
    WaitCertificateVerify(TrafficPair, V::Peer, PublicKey),
    /// The client is authenticated, or was never asked to be.
    WaitFinished(TrafficPair),
    /// Both Finished messages are exchanged.
    Connected,
    /// The handshake failed.
    Failed,
}

/// What the server chose from a ClientHello.
#[derive(Debug)]
struct Negotiated {
    /// The suite.
    suite: CipherSuite,
    /// The server's secret in the chosen group.
    secret: KeyShareSecret,
    /// The shared secret.
    shared: [u8; 32],
    /// The schemes the client accepts, one of which the server's key can make.
    schemes: Vec<SignatureScheme>,
    /// Whether the client sent a server name the server acknowledges.
    server_name: bool,
}

/// The server side of a handshake.
#[derive(Debug)]
pub(crate) struct Server<V: Verifier> {
    /// What the server accepts and proves.
    config: ServerConfig,
    /// Where the handshake stands.
    state: ServerState<V>,
}

impl<V: Verifier> Server<V> {
    /// A server waiting for a ClientHello.
    pub(crate) const fn new(config: ServerConfig) -> Self {
        Self {
            config,
            state: ServerState::WaitClientHello,
        }
    }

    /// Whether the handshake is done.
    pub(crate) const fn is_connected(&self) -> bool {
        matches!(self.state, ServerState::Connected)
    }

    /// Keeps only the given TLS 1.3 suites as acceptable.
    pub(crate) fn restrict_suites(&mut self, suites: &[CipherSuite]) {
        self.config.suites = suites.to_vec();
    }

    /// Marks the handshake failed.
    pub(crate) fn fail(&mut self) {
        self.state = ServerState::Failed;
    }

    /// Advances by one received message.
    pub(crate) fn handle(
        &mut self,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<(), TlsError<V::Error>> {
        let state = mem::replace(&mut self.state, ServerState::Failed);
        self.state = match (state, message.kind()) {
            (ServerState::WaitClientHello, HandshakeType::CLIENT_HELLO) => {
                let traffic = self.client_hello(message, context)?;
                if self.config.client_auth.is_some() {
                    ServerState::WaitCertificate(traffic)
                } else {
                    ServerState::WaitFinished(traffic)
                }
            }
            (ServerState::WaitCertificate(traffic), HandshakeType::CERTIFICATE) => {
                let (peer, key) = context.read_certificate(message)?;
                ServerState::WaitCertificateVerify(traffic, peer, key)
            }
            (
                ServerState::WaitCertificateVerify(traffic, peer, key),
                HandshakeType::CERTIFICATE_VERIFY,
            ) => {
                let accepted = self.config.client_auth.as_deref().unwrap_or_default();
                context.read_certificate_verify(message, accepted, peer, &key)?;
                ServerState::WaitFinished(traffic)
            }
            (ServerState::WaitFinished(traffic), HandshakeType::FINISHED) => {
                let finished = Finished::parse(message.body())?;
                let hash = context.transcript.hash();
                if !traffic
                    .receiving(Role::Server)
                    .verify_finished(&hash, &finished.verify_data)
                {
                    return Err(ProtocolError::InvalidFinished.into());
                }
                context.transcript.update(message.raw());
                context.buffer.advance(Level::Application)?;
                ServerState::Connected
            }
            (ServerState::Connected, HandshakeType::KEY_UPDATE)
                if self.config.transport.quic_parameters().is_none() =>
            {
                let update = KeyUpdate::parse(message.body())?;
                context.output.push_back(TlsOutput::PeerKeyUpdate {
                    update_requested: update.update_requested,
                });
                ServerState::Connected
            }
            (state, _) => return Err(message.unexpected(state.waiting_for()).into()),
        };
        Ok(())
    }

    /// Negotiates from the ClientHello, then sends the whole server flight.
    ///
    /// # Returns
    ///
    /// The handshake traffic secrets, which check the client's flight.
    fn client_hello(
        &self,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<TrafficPair, TlsError<V::Error>> {
        let hello = ClientHello::parse(message.body())?;
        let mut negotiated = self.negotiate(&hello, context)?;
        context.transcript.update(message.raw());
        context.suite = Some(negotiated.suite);

        // Phase 1: the ServerHello at the Initial level, then the handshake keys.
        let public = negotiated.secret.public();
        let server_hello = context.send(ServerHello::encode(
            &context.randomness.random,
            hello.session_id,
            negotiated.suite,
            negotiated.secret.group(),
            &public,
        ));
        context.emit(Level::Initial, server_hello);
        // RFC 8446, appendix D.4: the dummy ChangeCipherSpec follows the ServerHello in compatibility mode.
        if !hello.session_id.is_empty() {
            context.output.push_back(TlsOutput::ChangeCipherSpec);
        }
        let handshake = HandshakeSecret::new(negotiated.suite, &negotiated.shared);
        negotiated.shared.fill(0);
        let traffic = handshake.traffic(&context.transcript.hash());
        context.output.push_back(TlsOutput::Keys {
            level: Level::Handshake,
            secrets: traffic.secrets(Role::Server),
        });

        // Phase 2: the encrypted flight, ending with Finished over all of it.
        let mut flight = context.send(EncryptedExtensions::encode(
            context.alpn.clone().as_deref(),
            negotiated.server_name,
            self.config.transport.quic_parameters(),
        ));
        if let Some(schemes) = &self.config.client_auth {
            flight.extend(context.send(CertificateRequest::encode(schemes)));
        }
        flight.extend(
            context.write_authentication(Some(&self.config.identity), &negotiated.schemes)?,
        );
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

    /// Checks the ClientHello against this server's configuration and picks every parameter.
    ///
    /// Every check names the rule it enforces:
    ///
    /// - TLS 1.3, through supported_versions, per RFC 8446, section 4.2.1;
    /// - no session id over QUIC, per RFC 9001, section 8.4;
    /// - a signature scheme the server's key can make;
    /// - a key share in a supported group, since a hello retry is not supported;
    /// - a common application protocol, per RFC 7301, section 3.2;
    /// - transport parameters over QUIC, per RFC 9001, section 8.2.
    fn negotiate(
        &self,
        hello: &ClientHello<'_>,
        context: &mut Context<V>,
    ) -> Result<Negotiated, TlsError<V::Error>> {
        if hello.legacy_version != LEGACY_VERSION {
            return Err(ProtocolError::InvalidLegacyVersion(hello.legacy_version).into());
        }
        let quic = self.config.transport.quic_parameters().is_some();
        if quic && !hello.session_id.is_empty() {
            return Err(ProtocolError::NonEmptySessionId(hello.session_id.len()).into());
        }
        let extensions = &hello.extensions;
        if !extensions
            .supported_versions()?
            .is_some_and(|versions| versions.contains(&TLS13))
        {
            return Err(ProtocolError::UnsupportedVersion.into());
        }
        let suite = self
            .config
            .suites
            .iter()
            .copied()
            .find(|suite| hello.cipher_suites.contains(&suite.code()))
            .ok_or(ProtocolError::NoCommonCipherSuite)?;
        let offered: Vec<SignatureScheme> = extensions
            .signature_algorithms()?
            .ok_or(ProtocolError::MissingExtension(
                ExtensionType::SIGNATURE_ALGORITHMS.0,
            ))?
            .into_iter()
            .map(SignatureScheme)
            .collect();
        if self.config.identity.key().choose_scheme(&offered).is_none() {
            return Err(ProtocolError::NoCommonSignatureScheme.into());
        }

        // RFC 8446, section 9.2: a key share comes with the supported groups.
        let shares = extensions
            .client_key_shares()?
            .ok_or(ProtocolError::MissingExtension(ExtensionType::KEY_SHARE.0))?;
        extensions
            .supported_groups()?
            .ok_or(ProtocolError::MissingExtension(
                ExtensionType::SUPPORTED_GROUPS.0,
            ))?;
        let (secret, share) = self
            .config
            .groups
            .iter()
            .find_map(|&group| {
                let &(_, share) = shares.iter().find(|(offered, _)| *offered == group.0)?;
                let bytes = if group == NamedGroup::SECP256R1 {
                    context.randomness.p256
                } else {
                    context.randomness.x25519
                };
                KeyShareSecret::new(group, bytes).map(|secret| (secret, share))
            })
            .ok_or(ProtocolError::NoKeyShare)?;
        let shared = secret.agree(share)?;

        // The first of the server's protocols the client offers.
        let protocols = extensions.alpn()?;
        let chosen = protocols.as_deref().and_then(|offered| {
            self.config
                .alpn
                .iter()
                .find(|protocol| offered.contains(&protocol.as_slice()))
        });
        match (chosen, protocols.is_some()) {
            (Some(protocol), _) => context.alpn = Some(protocol.clone()),
            // RFC 7301, section 3.2: no overlap with an offered list is fatal.
            (None, true) if !self.config.alpn.is_empty() => {
                return Err(ProtocolError::NoApplicationProtocol.into());
            }
            (None, _) if self.config.require_alpn => {
                return Err(ProtocolError::NoApplicationProtocol.into());
            }
            (None, _) => {}
        }

        if quic {
            let parameters = extensions.require(ExtensionType::QUIC_TRANSPORT_PARAMETERS)?;
            context.peer_transport_parameters = Some(parameters.to_vec());
        }
        Ok(Negotiated {
            suite,
            secret,
            shared,
            schemes: offered,
            server_name: extensions.get(ExtensionType::SERVER_NAME).is_some(),
        })
    }
}

impl<V: Verifier> ServerState<V> {
    /// What the state waits for, for error messages.
    const fn waiting_for(&self) -> &'static str {
        match self {
            Self::WaitClientHello => "waiting for ClientHello",
            Self::WaitCertificate(_) => "waiting for the client Certificate",
            Self::WaitCertificateVerify(..) => "waiting for the client CertificateVerify",
            Self::WaitFinished(_) => "waiting for the client Finished",
            Self::Connected => "connected, where only key updates may arrive",
            Self::Failed => "failed",
        }
    }
}
