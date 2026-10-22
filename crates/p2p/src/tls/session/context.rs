//! What both roles share during a handshake: the transcript, the outputs, and what was learned.

use std::{collections::VecDeque, sync::Arc};

use axiom_crypto::{
    p256::PublicKey as CertificateKey,
    x25519::{PublicKey as KeySharePublic, SecretKey as KeyShareSecret},
};
use sha2::{Digest, Sha256};

use crate::{
    identity::PeerId,
    tls::{
        CipherSuite, EcdsaSigValue, Level, TlsError, TlsIdentity, TlsOutput, VerifiedPeer,
        buffer::HandshakeBuffer,
        key_schedule::{Role, Transcript},
        message::{CertificateMessage, CertificateVerify, ECDSA_SECP256R1_SHA256, Message, X25519},
    },
};

/// The state every handshake step reads or extends, whatever the role.
#[derive(Debug)]
pub(crate) struct Context {
    /// This side's role.
    pub(crate) role: Role,
    /// This node's certificate and key.
    pub(crate) identity: Arc<TlsIdentity>,
    /// This side's encoded transport parameters.
    pub(crate) transport_parameters: Vec<u8>,
    /// The peer the client means to reach, if known.
    pub(crate) expected: Option<PeerId>,
    /// Seconds since the epoch, for the certificate validity check.
    pub(crate) now: u64,
    /// This side's hello random.
    pub(crate) random: [u8; 32],
    /// The suites this side accepts, in order of preference.
    pub(crate) suites: Vec<CipherSuite>,
    /// The incoming bytes not yet framed.
    pub(crate) buffer: HandshakeBuffer,
    /// The hash of every message so far.
    pub(crate) transcript: Transcript,
    /// Outputs not yet taken, in order.
    pub(crate) output: VecDeque<TlsOutput>,
    /// The negotiated suite.
    pub(crate) suite: Option<CipherSuite>,
    /// The peer's encoded transport parameters.
    pub(crate) peer_transport_parameters: Option<Vec<u8>>,
    /// The peer, once its CertificateVerify checks out.
    pub(crate) peer: Option<VerifiedPeer>,
}

impl Context {
    /// Records a message this side sends: into the transcript, and returned for the flight.
    pub(crate) fn send(&mut self, message: Vec<u8>) -> Vec<u8> {
        self.transcript.update(&message);
        message
    }

    /// Queues handshake bytes for a level.
    pub(crate) fn emit(&mut self, level: Level, bytes: Vec<u8>) {
        self.output.push_back(TlsOutput::Handshake { level, bytes });
    }

    /// The X25519 shared secret with a peer's share.
    pub(crate) fn agree(
        secret: &KeyShareSecret,
        group: u16,
        share: &[u8],
    ) -> Result<[u8; 32], TlsError> {
        let invalid = TlsError::InvalidKeyShare {
            group,
            length: share.len(),
        };
        if group != X25519 {
            return Err(invalid);
        }
        let share: [u8; 32] = share.try_into().map_err(|_| invalid)?;
        let shared = secret
            .diffie_hellman(&KeySharePublic::from_bytes(share))
            .map_err(|_| TlsError::LowOrderKeyShare)?;
        Ok(*shared.as_bytes())
    }

    /// Checks the peer's Certificate message and authenticates the peer it names.
    pub(crate) fn read_certificate(
        &mut self,
        message: &Message,
    ) -> Result<(VerifiedPeer, CertificateKey), TlsError> {
        let certificate = CertificateMessage::parse(message.body())?;
        // The request context is empty in the handshake, so its echo is too.
        if !certificate.context.is_empty() {
            return Err(TlsError::NonEmptyRequestContext(certificate.context.len()));
        }
        let (der, extensions) = match certificate.entries.as_slice() {
            [] => return Err(TlsError::CertificateRequired),
            [entry] => *entry,
            entries => return Err(TlsError::MultipleCertificates(entries.len())),
        };
        // No certificate extension was requested, so none may come back.
        if !extensions.is_empty() {
            return Err(TlsError::CertificateExtensions);
        }
        let (peer, key) = VerifiedPeer::authenticate(der, self.now)?;
        if let Some(expected) = &self.expected
            && *expected != peer.peer_id
        {
            return Err(TlsError::PeerIdMismatch {
                expected: expected.clone(),
                actual: peer.peer_id,
            });
        }
        self.transcript.update(message.raw());
        Ok((peer, key))
    }

    /// Checks the peer's CertificateVerify over the transcript, then records the peer as verified.
    pub(crate) fn read_certificate_verify(
        &mut self,
        message: &Message,
        peer: VerifiedPeer,
        key: &CertificateKey,
    ) -> Result<(), TlsError> {
        let verify = CertificateVerify::parse(message.body())?;
        if verify.scheme != ECDSA_SECP256R1_SHA256 {
            return Err(TlsError::UnofferedSignatureScheme(verify.scheme));
        }
        let context = match self.role {
            Role::Client => CertificateVerify::SERVER_CONTEXT,
            Role::Server => CertificateVerify::CLIENT_CONTEXT,
        };
        let content = CertificateVerify::signed_content(context, &self.transcript.hash());
        let hash: [u8; 32] = Sha256::digest(&content).into();
        let valid = EcdsaSigValue::from_der(verify.signature)
            .is_ok_and(|value| key.verify(&hash, &value.signature()).is_ok());
        if !valid {
            return Err(TlsError::InvalidCertificateVerify);
        }
        self.transcript.update(message.raw());
        self.peer = Some(peer);
        Ok(())
    }

    /// This side's Certificate and CertificateVerify messages, added to the transcript.
    pub(crate) fn write_authentication(&mut self) -> Vec<u8> {
        let certificate = self.send(CertificateMessage::encode(self.identity.certificate()));
        let context = match self.role {
            Role::Client => CertificateVerify::CLIENT_CONTEXT,
            Role::Server => CertificateVerify::SERVER_CONTEXT,
        };
        let content = CertificateVerify::signed_content(context, &self.transcript.hash());
        let verify = self.send(CertificateVerify::encode(&self.identity.sign(&content)));
        [certificate, verify].concat()
    }
}
