//! What both roles share during a handshake: the transcript, the outputs, and what was learned.

use std::{collections::VecDeque, sync::Arc};

use crate::{
    CertifiedKey, CipherSuite, Level, ProtocolError, Randomness, SignatureScheme, TlsError,
    TlsOutput, Verifier,
    buffer::HandshakeBuffer,
    key_schedule::{Role, Transcript},
    message::{CertificateMessage, CertificateVerify, HandshakeType, Message},
    x509::PublicKey,
};

/// The state every handshake step reads or extends, whatever the role.
#[derive(Debug)]
pub(crate) struct Context<V: Verifier> {
    /// This side's role.
    pub(crate) role: Role,
    /// Who checks the peer's certificates; a server without client authentication has none.
    pub(crate) verifier: Option<V>,
    /// Seconds since the epoch, for certificate validity.
    pub(crate) now: u64,
    /// The random values this handshake consumes.
    pub(crate) randomness: Randomness,
    /// The incoming bytes not yet framed.
    pub(crate) buffer: HandshakeBuffer,
    /// The hash of every message so far.
    pub(crate) transcript: Transcript,
    /// Outputs not yet taken, in order.
    pub(crate) output: VecDeque<TlsOutput>,
    /// The negotiated TLS 1.3 suite.
    pub(crate) suite: Option<CipherSuite>,
    /// The negotiated application protocol.
    pub(crate) alpn: Option<Vec<u8>>,
    /// The peer's encoded QUIC transport parameters.
    pub(crate) peer_transport_parameters: Option<Vec<u8>>,
    /// The peer, once its certificate and signature check out.
    pub(crate) peer: Option<V::Peer>,
}

impl<V: Verifier> Context<V> {
    /// The shared state of a fresh handshake.
    pub(crate) fn new(role: Role, verifier: Option<V>, randomness: Randomness, now: u64) -> Self {
        Self {
            role,
            verifier,
            now,
            randomness,
            buffer: HandshakeBuffer::new(Level::Initial),
            transcript: Transcript::new(),
            output: VecDeque::new(),
            suite: None,
            alpn: None,
            peer_transport_parameters: None,
            peer: None,
        }
    }

    /// Records a message this side sends: into the transcript, and returned for the flight.
    pub(crate) fn send(&mut self, message: Vec<u8>) -> Vec<u8> {
        self.transcript.update(&message);
        message
    }

    /// Queues handshake bytes for a level.
    pub(crate) fn emit(&mut self, level: Level, bytes: Vec<u8>) {
        self.output.push_back(TlsOutput::Handshake { level, bytes });
    }

    /// Checks the peer's TLS 1.3 Certificate message and the chain it carries.
    pub(crate) fn read_certificate(
        &mut self,
        message: &Message,
    ) -> Result<(V::Peer, PublicKey), TlsError<V::Error>> {
        let certificate = CertificateMessage::parse(message.body())?;
        // The request context is empty in the handshake, so its echo is too.
        if !certificate.context.is_empty() {
            return Err(ProtocolError::NonEmptyRequestContext(certificate.context.len()).into());
        }
        // No status or timestamp extension was requested, so no entry may carry one.
        if certificate
            .entries
            .iter()
            .any(|(_, extensions)| !extensions.is_empty())
        {
            return Err(ProtocolError::CertificateExtensions.into());
        }
        let chain: Vec<&[u8]> = certificate.entries.iter().map(|&(der, _)| der).collect();
        let verified = self.verify_chain(&chain)?;
        self.transcript.update(message.raw());
        Ok(verified)
    }

    /// Runs the verifier over a chain, which must not be empty.
    pub(crate) fn verify_chain(
        &self,
        chain: &[&[u8]],
    ) -> Result<(V::Peer, PublicKey), TlsError<V::Error>> {
        if chain.is_empty() {
            return Err(ProtocolError::CertificateRequired.into());
        }
        let verifier = self
            .verifier
            .as_ref()
            .ok_or(ProtocolError::UnexpectedMessage {
                found: HandshakeType::CERTIFICATE.0,
                state: "not requesting a certificate",
            })?;
        verifier
            .verify(chain, self.now)
            .map_err(TlsError::Certificate)
    }

    /// Checks the peer's CertificateVerify over the transcript, then records the peer.
    ///
    /// The scheme must be one this side accepts, allowed in TLS 1.3, and fit the peer's key.
    pub(crate) fn read_certificate_verify(
        &mut self,
        message: &Message,
        accepted: &[SignatureScheme],
        peer: V::Peer,
        key: &PublicKey,
    ) -> Result<(), TlsError<V::Error>> {
        let verify = CertificateVerify::parse(message.body())?;
        let scheme = verify.scheme;
        if !accepted.contains(&scheme) || !scheme.allowed_in_tls13() || !scheme.fits_tls13(key) {
            return Err(ProtocolError::UnofferedSignatureScheme(scheme.0).into());
        }
        let context = match self.role {
            Role::Client => CertificateVerify::SERVER_CONTEXT,
            Role::Server => CertificateVerify::CLIENT_CONTEXT,
        };
        let content = CertificateVerify::signed_content(context, &self.transcript.hash());
        if scheme
            .verify(key, &content, verify.signature, true)
            .is_err()
        {
            return Err(ProtocolError::InvalidCertificateVerify.into());
        }
        self.transcript.update(message.raw());
        self.peer = Some(peer);
        Ok(())
    }

    /// This side's Certificate and CertificateVerify messages, added to the transcript.
    ///
    /// Without an identity, only an empty Certificate message goes out.
    pub(crate) fn write_authentication(
        &mut self,
        identity: Option<&Arc<CertifiedKey>>,
        peer_schemes: &[SignatureScheme],
    ) -> Result<Vec<u8>, TlsError<V::Error>> {
        let Some(identity) = identity else {
            return Ok(self.send(CertificateMessage::encode::<Vec<u8>>(&[])));
        };
        let scheme = identity
            .key()
            .choose_scheme(peer_schemes)
            .ok_or(ProtocolError::NoCommonSignatureScheme)?;
        let certificate = self.send(CertificateMessage::encode(identity.chain()));
        let context = match self.role {
            Role::Client => CertificateVerify::CLIENT_CONTEXT,
            Role::Server => CertificateVerify::SERVER_CONTEXT,
        };
        let content = CertificateVerify::signed_content(context, &self.transcript.hash());
        let signature = identity
            .key()
            .sign(scheme, &content, &self.randomness.salt)
            .map_err(|_| ProtocolError::SigningFailed)?;
        let verify = self.send(CertificateVerify::encode(scheme, &signature));
        Ok([certificate, verify].concat())
    }
}
