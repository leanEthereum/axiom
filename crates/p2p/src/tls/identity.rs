//! This node's TLS identity: a certificate key and the certificate binding it to the host key.

use axiom_crypto::p256::SecretKey;
use sha2::{Digest, Sha256};

use super::{EcdsaSigValue, TlsError, certificate::CertificateBuilder};
use crate::identity::Keypair;

/// This node's TLS identity: an ephemeral certificate key and its libp2p certificate.
///
/// One identity may serve many connections; the libp2p TLS spec allows reuse.
#[derive(Debug)]
pub struct TlsIdentity {
    /// The P-256 certificate key; it clears itself when dropped.
    key: SecretKey,
    /// The DER certificate.
    certificate: Vec<u8>,
}

impl TlsIdentity {
    /// A fresh self-signed certificate binding the host key.
    ///
    /// The certificate is valid from the epoch to the end of 9999, so no clock is read.
    ///
    /// # Arguments
    ///
    /// - `host`: the secp256k1 identity, which signs the extension.
    /// - `seed`: 32 bytes of operating system entropy, used as the certificate key.
    ///
    /// # Errors
    ///
    /// Fails when the seed is zero or not below the P-256 group order, with odds near 2^-32.
    pub fn generate(host: &Keypair, seed: [u8; 32]) -> Result<Self, TlsError> {
        let key = SecretKey::from_bytes(&seed).map_err(|_| TlsError::InvalidSeed)?;
        let certificate = CertificateBuilder::new(&key).build(host);
        Ok(Self { key, certificate })
    }

    /// The DER certificate.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Signs content with the certificate key: ECDSA over its SHA-256 hash, DER-encoded.
    ///
    /// The signing runs in constant time.
    pub(crate) fn sign(&self, content: &[u8]) -> Vec<u8> {
        let hash: [u8; 32] = Sha256::digest(content).into();
        EcdsaSigValue::from(self.key.sign(&hash)).to_der()
    }

    /// An identity with a hand-made certificate, for tests of malformed peers.
    #[cfg(test)]
    pub(crate) const fn with_certificate(key: SecretKey, certificate: Vec<u8>) -> Self {
        Self { key, certificate }
    }
}
