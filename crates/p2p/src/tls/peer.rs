//! A peer authenticated by its libp2p certificate.

use axiom_crypto::p256::PublicKey as CertificateKey;

use super::{
    TlsError,
    certificate::{ParsedCertificate, SignedKey},
    der::Timestamp,
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
        Self::authenticate(certificate, now_unix_secs).map(|(peer, _)| peer)
    }

    /// The same checks, also returning the certificate key.
    pub(crate) fn authenticate(
        certificate: &[u8],
        now_unix_secs: u64,
    ) -> Result<(Self, CertificateKey), TlsError> {
        let parsed = ParsedCertificate::parse(certificate)?;
        parsed.verify_signature()?;
        parsed.check_validity(Timestamp::from_unix_secs(now_unix_secs))?;
        let public_key = SignedKey::from_der(parsed.signed_key())?.verify(parsed.key_encoding())?;
        let peer = Self {
            peer_id: PeerId::from_public_key(&public_key),
            public_key,
        };
        Ok((peer, *parsed.key().key()))
    }
}
