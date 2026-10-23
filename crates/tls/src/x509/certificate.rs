//! Parsing one X.509 certificate into the fields its checks read.

use super::{Extensions, Name, PublicKey, SignatureAlgorithm, X509Error};
use crate::der::{DerReader, Tag, Timestamp};

/// Most content bytes of a serial number: 20 octets, plus a sign byte some encoders add.
///
/// RFC 5280, section 4.1.2.2, caps the serial at 20 octets.
const MAX_SERIAL_LEN: usize = 21;

/// The version an X.509 certificate declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    /// Version 1: no extensions, the default when the field is absent.
    V1,
    /// Version 3: the version that carries extensions.
    V3,
}

/// The validity window of a certificate, both ends included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Validity {
    /// The first instant the certificate is valid.
    pub not_before: Timestamp,
    /// The last instant the certificate is valid.
    pub not_after: Timestamp,
}

impl Validity {
    /// Whether an instant lies in the window.
    #[must_use]
    pub fn contains(&self, now: Timestamp) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

/// A parsed certificate, borrowing its DER.
///
/// ```text
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
/// TBSCertificate ::= SEQUENCE {
///     version [0] DEFAULT v1, serialNumber, signature, issuer, validity, subject,
///     subjectPublicKeyInfo, issuerUniqueID [1], subjectUniqueID [2], extensions [3] }
/// ```
///
/// See RFC 5280, section 4.1.
/// Parsing checks structure only; the signature, dates and extensions are checked by the caller.
#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    /// The whole certificate.
    der: &'a [u8],
    /// The whole encoding of the signed part.
    tbs: &'a [u8],
    /// The signature algorithm's whole encoding, checked equal to the inner one.
    signature_algorithm: &'a [u8],
    /// The signature bytes.
    signature: &'a [u8],
    /// The declared version.
    version: Version,
    /// The serial number's content bytes.
    serial: &'a [u8],
    /// The issuer name.
    issuer: Name<'a>,
    /// The validity window.
    validity: Validity,
    /// The subject name.
    subject: Name<'a>,
    /// The SubjectPublicKeyInfo's whole encoding.
    public_key_info: &'a [u8],
    /// Whether a deprecated issuer or subject unique identifier is present.
    unique_identifier: bool,
    /// The extensions; empty for a v1 certificate.
    extensions: Extensions<'a>,
}

impl<'a> Certificate<'a> {
    /// Parses a DER certificate.
    ///
    /// # Errors
    ///
    /// Fails on malformed DER, an unknown version, an over-long serial, or mismatched algorithms.
    pub fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        let mut outer = DerReader::new(der);
        let mut certificate = outer.sequence()?;
        outer.finish()?;
        let (tbs_content, tbs) = certificate.element_with_encoding(Tag::SEQUENCE)?;
        let (_, signature_algorithm) = certificate.element_with_encoding(Tag::SEQUENCE)?;
        let signature = certificate.bit_string()?;
        certificate.finish()?;

        let mut fields = DerReader::new(tbs_content);
        let version = match fields.optional(Tag::explicit(0))? {
            // DER omits the default v1, so a written version is v2 or v3.
            None => Version::V1,
            Some(content) => {
                let mut reader = DerReader::new(content);
                let number = reader.small_integer()?;
                reader.finish()?;
                match number {
                    2 => Version::V3,
                    other => return Err(X509Error::UnsupportedVersion(other)),
                }
            }
        };

        // The serial may be negative or zero in the wild; only its length is bounded.
        let serial = fields.integer()?;
        if serial.len() > MAX_SERIAL_LEN {
            return Err(X509Error::SerialTooLong {
                length: serial.len(),
                max: MAX_SERIAL_LEN,
            });
        }

        let (_, inner_algorithm) = fields.element_with_encoding(Tag::SEQUENCE)?;
        if inner_algorithm != signature_algorithm {
            return Err(X509Error::AlgorithmMismatch);
        }

        let issuer = Name::read(&mut fields)?;
        let mut window = fields.sequence()?;
        let validity = Validity {
            not_before: Timestamp::read(&mut window)?,
            not_after: Timestamp::read(&mut window)?,
        };
        window.finish()?;
        let subject = Name::read(&mut fields)?;
        let (_, public_key_info) = fields.element_with_encoding(Tag::SEQUENCE)?;

        // RFC 5280, section 4.1.2.8: unique identifiers are deprecated, IMPLICIT BIT STRINGs.
        let mut unique_identifier = false;
        for tag in [Tag::implicit(1), Tag::implicit(2)] {
            if fields.optional(tag)?.is_some() {
                unique_identifier = true;
            }
        }

        let extensions = match fields.optional(Tag::explicit(3))? {
            None => Extensions::default(),
            Some(_) if version == Version::V1 => return Err(X509Error::UnsupportedVersion(0)),
            Some(content) => {
                let mut wrapper = DerReader::new(content);
                let list = wrapper.element(Tag::SEQUENCE)?;
                wrapper.finish()?;
                Extensions::read(list)?
            }
        };
        fields.finish()?;

        Ok(Self {
            der,
            tbs,
            signature_algorithm,
            signature,
            version,
            serial,
            issuer,
            validity,
            subject,
            public_key_info,
            unique_identifier,
            extensions,
        })
    }

    /// The whole certificate.
    #[must_use]
    pub const fn der(&self) -> &'a [u8] {
        self.der
    }

    /// The whole encoding of the signed part.
    #[must_use]
    pub const fn tbs(&self) -> &'a [u8] {
        self.tbs
    }

    /// The signature algorithm's whole encoding.
    #[must_use]
    pub const fn signature_algorithm(&self) -> &'a [u8] {
        self.signature_algorithm
    }

    /// The signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8] {
        self.signature
    }

    /// The declared version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The serial number's content bytes.
    #[must_use]
    pub const fn serial(&self) -> &'a [u8] {
        self.serial
    }

    /// The issuer name.
    #[must_use]
    pub const fn issuer(&self) -> &Name<'a> {
        &self.issuer
    }

    /// The validity window.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The subject name.
    #[must_use]
    pub const fn subject(&self) -> &Name<'a> {
        &self.subject
    }

    /// The SubjectPublicKeyInfo's whole encoding.
    #[must_use]
    pub const fn public_key_info(&self) -> &'a [u8] {
        self.public_key_info
    }

    /// Whether a deprecated unique identifier is present.
    #[must_use]
    pub const fn has_unique_identifier(&self) -> bool {
        self.unique_identifier
    }

    /// The extensions.
    #[must_use]
    pub const fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }

    /// The subject public key.
    ///
    /// # Errors
    ///
    /// Fails on an unsupported algorithm or an invalid key.
    pub fn public_key(&self) -> Result<PublicKey, X509Error> {
        PublicKey::from_spki(self.public_key_info)
    }

    /// Checks the signature over the signed part under an issuer's key.
    ///
    /// # Errors
    ///
    /// Fails on an unsupported or incompatible algorithm, or a signature that does not verify.
    pub fn verify_signed_by(&self, issuer: &PublicKey) -> Result<(), X509Error> {
        let algorithm = SignatureAlgorithm::from_der(self.signature_algorithm)?;
        issuer.verify(algorithm, self.tbs, self.signature)
    }
}
