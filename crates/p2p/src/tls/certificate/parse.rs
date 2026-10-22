//! The libp2p certificate profile, checked over a strictly parsed X.509 certificate.

use axiom_crypto::p256::PublicKey as CertificateKey;
use axiom_tls::{
    der::Timestamp,
    x509::{Certificate, PublicKey, SignatureAlgorithm, Version, X509Error},
};

use super::{CertificateError, LIBP2P_EXTENSION_OID};

/// A certificate that fits the libp2p profile, down to the fields its checks need.
///
/// The profile, per the libp2p TLS spec and RFC 5280:
///
/// - X.509 v3, signed with ecdsa-with-SHA256 by its own P-256 key;
/// - no unique identifiers;
/// - the libp2p extension present, and no other critical extension.
#[derive(Clone, Debug)]
pub(crate) struct ParsedCertificate<'a> {
    /// The certificate.
    certificate: Certificate<'a>,
    /// The certificate key.
    key: CertificateKey,
    /// The content of the libp2p public key extension.
    signed_key: &'a [u8],
}

impl<'a> ParsedCertificate<'a> {
    /// Parses a DER certificate, refusing anything outside the libp2p profile.
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, CertificateError> {
        let certificate = Certificate::parse(der)?;
        if certificate.version() != Version::V3 {
            return Err(X509Error::UnsupportedVersion(0).into());
        }
        let algorithm = SignatureAlgorithm::from_der(certificate.signature_algorithm())
            .map_err(|_| CertificateError::UnsupportedSignatureAlgorithm)?;
        if algorithm != SignatureAlgorithm::EcdsaSha256 {
            return Err(CertificateError::UnsupportedSignatureAlgorithm);
        }
        let key = match certificate.public_key() {
            Ok(PublicKey::P256(key)) => key,
            Ok(_) | Err(X509Error::UnsupportedKeyAlgorithm) => {
                return Err(CertificateError::UnsupportedKeyAlgorithm);
            }
            Err(error) => return Err(error.into()),
        };
        // RFC 5280, section 4.1.2.8: the unique identifiers are deprecated, and libp2p forbids them.
        if certificate.has_unique_identifier() {
            return Err(CertificateError::UniqueIdentifier);
        }
        let signed_key = Self::find_extension(&certificate)?;
        Ok(Self {
            certificate,
            key,
            signed_key,
        })
    }

    /// Checks the self-signature over the signed part, under the certificate key.
    pub(crate) fn verify_signature(&self) -> Result<(), CertificateError> {
        self.certificate
            .verify_signed_by(&PublicKey::P256(self.key))
            .map_err(|_| CertificateError::InvalidSelfSignature)
    }

    /// Checks the instant lies in the validity window, both ends included.
    pub(crate) fn check_validity(&self, now: Timestamp) -> Result<(), CertificateError> {
        let validity = self.certificate.validity();
        if now < validity.not_before {
            return Err(CertificateError::NotYetValid {
                not_before: validity.not_before.unix_seconds(),
                now: now.unix_seconds(),
            });
        }
        if now > validity.not_after {
            return Err(CertificateError::Expired {
                not_after: validity.not_after.unix_seconds(),
                now: now.unix_seconds(),
            });
        }
        Ok(())
    }

    /// The certificate key.
    pub(crate) const fn key(&self) -> &CertificateKey {
        &self.key
    }

    /// The certificate key's whole SubjectPublicKeyInfo encoding.
    pub(crate) const fn key_encoding(&self) -> &'a [u8] {
        self.certificate.public_key_info()
    }

    /// The content of the libp2p public key extension.
    pub(crate) const fn signed_key(&self) -> &'a [u8] {
        self.signed_key
    }

    /// Returns the libp2p extension, refusing any other critical one.
    ///
    /// Per RFC 5280, section 4.2, and the libp2p TLS spec, an unknown non-critical extension is ignored.
    fn find_extension(certificate: &Certificate<'a>) -> Result<&'a [u8], CertificateError> {
        let mut found = None;
        for extension in certificate.extensions().iter() {
            if extension.oid == LIBP2P_EXTENSION_OID {
                found = Some(extension.value);
            } else if extension.critical {
                return Err(CertificateError::UnknownCriticalExtension);
            }
        }
        found.ok_or(CertificateError::MissingExtension)
    }
}
