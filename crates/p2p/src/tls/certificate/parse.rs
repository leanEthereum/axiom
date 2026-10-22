//! Strict parsing of a libp2p certificate, down to the fields its checks need.

use sha2::{Digest, Sha256};

use super::{CertificateError, ECDSA_WITH_SHA256_OID, LIBP2P_EXTENSION_OID, SubjectPublicKeyInfo};
use crate::tls::{
    EcdsaSigValue,
    der::{DerError, DerReader, Tag, Timestamp},
};

/// The version field value of an X.509 v3 certificate.
const VERSION_3: u64 = 2;

/// Longest serial number RFC 5280, section 4.1.2.2, allows: 20 bytes.
const MAX_SERIAL_LEN: usize = 20;

/// The parts of a certificate that its checks read.
///
/// ```text
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
/// TBSCertificate ::= SEQUENCE {
///     version [0] INTEGER, serialNumber, signature, issuer, validity, subject,
///     subjectPublicKeyInfo, issuerUniqueID [1], subjectUniqueID [2], extensions [3]
/// }
/// ```
///
/// See RFC 5280, section 4.1.
#[derive(Clone, Debug)]
pub(crate) struct ParsedCertificate<'a> {
    /// The whole encoding of the signed part.
    tbs: &'a [u8],
    /// The self-signature.
    signature: EcdsaSigValue,
    /// The certificate key.
    key: SubjectPublicKeyInfo,
    /// The certificate key's whole encoding, which the host key signs.
    key_encoding: &'a [u8],
    /// Start of the validity window.
    not_before: Timestamp,
    /// End of the validity window.
    not_after: Timestamp,
    /// The content of the libp2p public key extension.
    signed_key: &'a [u8],
}

impl<'a> ParsedCertificate<'a> {
    /// Parses a DER certificate, refusing anything outside the libp2p profile.
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, CertificateError> {
        let mut outer = DerReader::new(der);
        let mut certificate = outer.sequence()?;
        outer.finish()?;
        let (tbs_content, tbs) = certificate.element_with_encoding(Tag::SEQUENCE)?;
        let (_, outer_algorithm) = certificate.element_with_encoding(Tag::SEQUENCE)?;
        let signature = certificate.bit_string()?;
        certificate.finish()?;

        let mut fields = DerReader::new(tbs_content);

        // Version: v3 is required, since only v3 carries extensions.
        if fields.peek_tag() != Some(Tag::explicit(0)) {
            return Err(CertificateError::UnsupportedVersion(0));
        }
        let mut version = DerReader::new(fields.element(Tag::explicit(0))?);
        let number = version.small_integer()?;
        version.finish()?;
        if number != VERSION_3 {
            return Err(CertificateError::UnsupportedVersion(number));
        }

        // Serial number: positive and at most 20 bytes; its value is not used.
        let serial = fields.unsigned_integer()?;
        if serial.len() > MAX_SERIAL_LEN {
            return Err(DerError::IntegerTooLong {
                length: serial.len(),
                max: MAX_SERIAL_LEN,
            }
            .into());
        }

        // Signature algorithm: equal to the outer one, and ecdsa-with-SHA256.
        let (_, inner_algorithm) = fields.element_with_encoding(Tag::SEQUENCE)?;
        if inner_algorithm != outer_algorithm {
            return Err(CertificateError::AlgorithmMismatch);
        }
        Self::check_algorithm(inner_algorithm)?;
        let signature = EcdsaSigValue::from_der(signature)?;

        // Issuer and subject names: any well-formed sequence, since nothing reads them.
        fields.sequence()?;
        let mut validity = fields.sequence()?;
        let not_before = Timestamp::read(&mut validity)?;
        let not_after = Timestamp::read(&mut validity)?;
        validity.finish()?;
        fields.sequence()?;

        let (_, key_encoding) = fields.element_with_encoding(Tag::SEQUENCE)?;
        let key = SubjectPublicKeyInfo::from_der(key_encoding)?;

        // RFC 5280, section 4.1.2.8: the unique identifiers are deprecated, and libp2p forbids them.
        for tag in [Tag::implicit(1), Tag::implicit(2)] {
            if fields.peek_tag() == Some(tag) {
                return Err(CertificateError::UniqueIdentifier);
            }
        }

        // Extensions: required, since the libp2p extension must be present.
        if fields.peek_tag() != Some(Tag::explicit(3)) {
            return Err(CertificateError::MissingExtension);
        }
        let mut wrapper = DerReader::new(fields.element(Tag::explicit(3))?);
        let extensions = wrapper.sequence()?;
        wrapper.finish()?;
        fields.finish()?;
        let signed_key = Self::find_extension(extensions)?;

        Ok(Self {
            tbs,
            signature,
            key,
            key_encoding,
            not_before,
            not_after,
            signed_key,
        })
    }

    /// Checks the self-signature over the signed part, under the certificate key.
    pub(crate) fn verify_signature(&self) -> Result<(), CertificateError> {
        let hash: [u8; 32] = Sha256::digest(self.tbs).into();
        self.key
            .key()
            .verify(&hash, &self.signature.signature())
            .map_err(|_| CertificateError::InvalidSelfSignature)
    }

    /// Checks the instant lies in the validity window, both ends included.
    pub(crate) fn check_validity(&self, now: Timestamp) -> Result<(), CertificateError> {
        if now < self.not_before {
            return Err(CertificateError::NotYetValid {
                not_before: self.not_before.unix_seconds(),
                now: now.unix_seconds(),
            });
        }
        if now > self.not_after {
            return Err(CertificateError::Expired {
                not_after: self.not_after.unix_seconds(),
                now: now.unix_seconds(),
            });
        }
        Ok(())
    }

    /// The certificate key.
    pub(crate) const fn key(&self) -> &SubjectPublicKeyInfo {
        &self.key
    }

    /// The certificate key's whole encoding.
    pub(crate) const fn key_encoding(&self) -> &'a [u8] {
        self.key_encoding
    }

    /// The content of the libp2p public key extension.
    pub(crate) const fn signed_key(&self) -> &'a [u8] {
        self.signed_key
    }

    /// Refuses any signature algorithm but ecdsa-with-SHA256, written without parameters.
    fn check_algorithm(encoding: &[u8]) -> Result<(), CertificateError> {
        // RFC 5758, section 3.2: the parameters field is absent.
        let mut outer = DerReader::new(encoding);
        let mut algorithm = outer.sequence()?;
        let oid = algorithm.object_identifier()?;
        if oid != ECDSA_WITH_SHA256_OID || !algorithm.is_empty() {
            return Err(CertificateError::UnsupportedSignatureAlgorithm);
        }
        Ok(())
    }

    /// Walks the extensions and returns the libp2p one.
    ///
    /// Per RFC 5280, section 4.2, and the libp2p TLS spec:
    ///
    /// - each extension appears at most once;
    /// - an unknown critical extension aborts;
    /// - an unknown non-critical extension is ignored.
    fn find_extension(mut extensions: DerReader<'a>) -> Result<&'a [u8], CertificateError> {
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut found = None;
        while !extensions.is_empty() {
            let mut extension = extensions.sequence()?;
            let oid = extension.object_identifier()?;

            // critical BOOLEAN DEFAULT FALSE: DER omits the default, so only true is written.
            let critical = if extension.peek_tag() == Some(Tag::BOOLEAN) {
                if !extension.boolean()? {
                    return Err(CertificateError::ExplicitDefault);
                }
                true
            } else {
                false
            };
            let value = extension.octet_string()?;
            extension.finish()?;

            if seen.contains(&oid) {
                return Err(CertificateError::DuplicateExtension);
            }
            seen.push(oid);
            if oid == LIBP2P_EXTENSION_OID {
                found = Some(value);
            } else if critical {
                return Err(CertificateError::UnknownCriticalExtension);
            }
        }
        found.ok_or(CertificateError::MissingExtension)
    }
}
