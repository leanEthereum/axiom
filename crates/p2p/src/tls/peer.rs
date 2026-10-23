//! A peer authenticated by its libp2p certificate, and the verifier the handshake asks.

use axiom_crypto::p256::PublicKey as CertificateKey;
use axiom_tls::{Verifier, der::Timestamp, x509::PublicKey as SubjectKey};

use super::{
    CertificateError, TlsError,
    certificate::{ParsedCertificate, SignedKey},
};
use crate::identity::{PeerId, PublicKey};

/// A peer authenticated by its libp2p certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The peer identifier derived from the host key.
    pub peer_id: PeerId,
    /// The host key the certificate extension carries.
    pub public_key: PublicKey,
}

impl VerifiedPeer {
    /// Checks a DER certificate under the libp2p TLS spec and returns the peer it authenticates.
    ///
    /// The checks run in this order:
    ///
    /// 1. strict DER and the X.509 v3 profile, with the libp2p extension present;
    /// 2. the self-signature, under the certificate key;
    /// 3. the validity window, at the given time;
    /// 4. the host key's signature over the certificate key.
    ///
    /// The certificate key, which then checks the TLS CertificateVerify, is not returned here.
    ///
    /// # Errors
    ///
    /// Fails with the first check that does not pass.
    pub fn from_certificate(certificate: &[u8], now_unix_secs: u64) -> Result<Self, TlsError> {
        Self::authenticate(certificate, now_unix_secs)
            .map(|(peer, _)| peer)
            .map_err(TlsError::Certificate)
    }

    /// The same checks, also returning the certificate key.
    pub(crate) fn authenticate(
        certificate: &[u8],
        now_unix_secs: u64,
    ) -> Result<(Self, CertificateKey), CertificateError> {
        let parsed = ParsedCertificate::parse(certificate)?;
        parsed.verify_signature()?;
        parsed.check_validity(Timestamp::from_unix_secs(now_unix_secs))?;
        let public_key = SignedKey::from_der(parsed.signed_key())?.verify(parsed.key_encoding())?;
        let peer = Self {
            peer_id: PeerId::from_public_key(&public_key),
            public_key,
        };
        Ok((peer, *parsed.key()))
    }
}

/// The libp2p verifier: one certificate, and the peer the dialer expects, if known.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Libp2pVerifier {
    /// The peer a dialer means to reach.
    pub(crate) expected: Option<PeerId>,
}

impl Verifier for Libp2pVerifier {
    type Peer = VerifiedPeer;
    type Error = CertificateError;

    fn verify(
        &self,
        chain: &[&[u8]],
        now_unix_secs: u64,
    ) -> Result<(VerifiedPeer, SubjectKey), CertificateError> {
        // The libp2p TLS spec: exactly one self-signed certificate.
        let [certificate] = chain else {
            return Err(CertificateError::MultipleCertificates(chain.len()));
        };
        let (peer, key) = VerifiedPeer::authenticate(certificate, now_unix_secs)?;
        if let Some(expected) = &self.expected
            && *expected != peer.peer_id
        {
            return Err(CertificateError::PeerIdMismatch {
                expected: expected.clone(),
                actual: peer.peer_id,
            });
        }
        Ok((peer, SubjectKey::P256(key)))
    }
}
