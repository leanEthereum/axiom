//! This node's TLS identity: a certificate key and the certificate binding it to the host key.

use std::sync::Arc;

use axiom_crypto::p256::SecretKey;
use axiom_tls::{CertifiedKey, SigningKey};

use super::{CertificateError, TlsError, certificate::CertificateBuilder};
use crate::identity::Keypair;

/// This node's TLS identity: an ephemeral certificate key and its libp2p certificate.
///
/// One identity may serve many connections; the libp2p TLS spec allows reuse.
#[derive(Debug)]
pub struct TlsIdentity {
    /// The certificate and its P-256 key, which clears itself when dropped.
    certified: Arc<CertifiedKey>,
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
        let invalid = || TlsError::Certificate(CertificateError::InvalidSeed);
        let key = SecretKey::from_bytes(&seed).map_err(|_| invalid())?;
        let certificate = CertificateBuilder::new(&key).build(host);
        // The builder wrote a certificate for this very key, so the pairing holds.
        let certified = CertifiedKey::new(vec![certificate], SigningKey::EcdsaP256(key))
            .map_err(|_| invalid())?;
        Ok(Self {
            certified: Arc::new(certified),
        })
    }

    /// The DER certificate.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        // Invariant: the chain holds exactly the one certificate written at construction.
        &self.certified.chain()[0]
    }

    /// The certificate and key, as the handshake signs with them.
    pub(crate) fn certified(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }

    /// An identity with a hand-made certificate, for tests of malformed peers.
    #[cfg(test)]
    pub(crate) fn with_certificate(key: SecretKey, certificate: Vec<u8>) -> Self {
        let certified = CertifiedKey::new(vec![certificate], SigningKey::EcdsaP256(key))
            .expect("the test certificate names the test key");
        Self {
            certified: Arc::new(certified),
        }
    }
}
