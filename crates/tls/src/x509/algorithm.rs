//! Signature algorithm identifiers, and the hash and padding each one names.

use super::{X509Error, oid};
use crate::{
    HashAlgorithm,
    der::{DerReader, Tag},
};

/// A certificate signature algorithm this stack verifies.
///
/// The set covers what public certificate authorities issue, per the CA/Browser Forum baseline requirements, section 7.1.3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// ECDSA over SHA-256.
    EcdsaSha256,
    /// ECDSA over SHA-384.
    EcdsaSha384,
    /// RSASSA-PKCS1-v1_5 over SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 over SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 over SHA-512.
    RsaPkcs1Sha512,
    /// RSASSA-PSS over SHA-256, with MGF1 over SHA-256 and a 32-byte salt.
    RsaPssSha256,
    /// RSASSA-PSS over SHA-384, with MGF1 over SHA-384 and a 48-byte salt.
    RsaPssSha384,
    /// RSASSA-PSS over SHA-512, with MGF1 over SHA-512 and a 64-byte salt.
    RsaPssSha512,
}

impl SignatureAlgorithm {
    /// Decodes a whole AlgorithmIdentifier.
    ///
    /// # Errors
    ///
    /// Fails on malformed DER and on any algorithm or parameters outside the supported set.
    pub fn from_der(encoding: &[u8]) -> Result<Self, X509Error> {
        let mut outer = DerReader::new(encoding);
        let mut identifier = outer.sequence()?;
        outer.finish()?;
        let algorithm = identifier.object_identifier()?;
        let parameters = identifier;

        // RFC 5758, section 3.2: ECDSA identifiers carry no parameters.
        let ecdsa = [
            (oid::ECDSA_WITH_SHA256, Self::EcdsaSha256),
            (oid::ECDSA_WITH_SHA384, Self::EcdsaSha384),
        ];
        if let Some(&(_, found)) = ecdsa.iter().find(|(known, _)| *known == algorithm) {
            return if parameters.is_empty() {
                Ok(found)
            } else {
                Err(X509Error::UnsupportedSignatureAlgorithm)
            };
        }

        // RFC 4055, section 5: the PKCS#1 identifiers carry NULL, which some encoders omit.
        let pkcs1 = [
            (oid::SHA256_WITH_RSA, Self::RsaPkcs1Sha256),
            (oid::SHA384_WITH_RSA, Self::RsaPkcs1Sha384),
            (oid::SHA512_WITH_RSA, Self::RsaPkcs1Sha512),
        ];
        if let Some(&(_, found)) = pkcs1.iter().find(|(known, _)| *known == algorithm) {
            return if Self::null_or_absent(parameters) {
                Ok(found)
            } else {
                Err(X509Error::UnsupportedSignatureAlgorithm)
            };
        }

        if algorithm == oid::RSASSA_PSS {
            return Self::pss(parameters);
        }
        Err(X509Error::UnsupportedSignatureAlgorithm)
    }

    /// The hash the signature is computed over.
    #[must_use]
    pub const fn hash(self) -> HashAlgorithm {
        match self {
            Self::EcdsaSha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => HashAlgorithm::Sha256,
            Self::EcdsaSha384 | Self::RsaPkcs1Sha384 | Self::RsaPssSha384 => HashAlgorithm::Sha384,
            Self::RsaPkcs1Sha512 | Self::RsaPssSha512 => HashAlgorithm::Sha512,
        }
    }

    /// Decodes RSASSA-PSS-params, accepting only a hash, MGF1 over the same hash, and a salt of its length.
    ///
    /// ```text
    /// RSASSA-PSS-params ::= SEQUENCE {
    ///     hashAlgorithm     [0] HashAlgorithm,
    ///     maskGenAlgorithm  [1] MaskGenAlgorithm,
    ///     saltLength        [2] INTEGER,
    ///     trailerField      [3] TrailerField DEFAULT trailerFieldBC }
    /// ```
    ///
    /// See RFC 4055, section 3.1.
    /// The defaults name SHA-1, which this stack refuses, so the first three fields must be present.
    fn pss(mut parameters: DerReader<'_>) -> Result<Self, X509Error> {
        let unsupported = X509Error::UnsupportedSignatureAlgorithm;
        let mut fields = parameters.sequence()?;
        parameters.finish()?;

        let mut hash_field = DerReader::new(fields.element(Tag::explicit(0))?);
        let hash = Self::hash_identifier(&mut hash_field)?;
        hash_field.finish()?;

        let mut mask_field = DerReader::new(fields.element(Tag::explicit(1))?);
        let mut mask = mask_field.sequence()?;
        mask_field.finish()?;
        if mask.object_identifier()? != oid::MGF1 {
            return Err(unsupported);
        }
        let mask_hash = Self::hash_identifier(&mut mask)?;
        mask.finish()?;

        let mut salt_field = DerReader::new(fields.element(Tag::explicit(2))?);
        let salt = salt_field.small_integer()?;
        salt_field.finish()?;

        // The trailer field defaults to 1; DER omits a default, so nothing may follow.
        fields.finish()?;
        let salt_matches = usize::try_from(salt).is_ok_and(|salt| salt == hash.output_len());
        if mask_hash != hash || !salt_matches {
            return Err(unsupported);
        }
        Ok(match hash {
            HashAlgorithm::Sha256 => Self::RsaPssSha256,
            HashAlgorithm::Sha384 => Self::RsaPssSha384,
            HashAlgorithm::Sha512 => Self::RsaPssSha512,
        })
    }

    /// Reads a hash AlgorithmIdentifier, whose parameters are NULL or absent per RFC 4055, section 2.1.
    fn hash_identifier(reader: &mut DerReader<'_>) -> Result<HashAlgorithm, X509Error> {
        let mut identifier = reader.sequence()?;
        let algorithm = identifier.object_identifier()?;
        if !Self::null_or_absent(identifier) {
            return Err(X509Error::UnsupportedSignatureAlgorithm);
        }
        [
            (oid::SHA256, HashAlgorithm::Sha256),
            (oid::SHA384, HashAlgorithm::Sha384),
            (oid::SHA512, HashAlgorithm::Sha512),
        ]
        .into_iter()
        .find_map(|(known, hash)| (known == algorithm).then_some(hash))
        .ok_or(X509Error::UnsupportedSignatureAlgorithm)
    }

    /// Whether the rest of an identifier is empty or exactly one NULL.
    fn null_or_absent(mut rest: DerReader<'_>) -> bool {
        rest.is_empty() || (rest.element(Tag::NULL).is_ok_and(<[u8]>::is_empty) && rest.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::DerWriter;

    /// An AlgorithmIdentifier with an OID and raw parameter bytes.
    fn identifier(algorithm: &[u8], parameters: &[u8]) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.sequence(|body| {
            body.element(Tag::OBJECT_IDENTIFIER, algorithm);
            body.encoded(parameters);
        });
        writer.into_bytes()
    }

    /// The PSS parameters for a hash, MGF1 hash and salt length.
    fn pss(hash: &[u8], mask_hash: &[u8], salt: u8) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.sequence(|params| {
            params.nested(Tag::explicit(0), |field| {
                field.sequence(|id| {
                    id.element(Tag::OBJECT_IDENTIFIER, hash);
                    id.element(Tag::NULL, &[]);
                });
            });
            params.nested(Tag::explicit(1), |field| {
                field.sequence(|mgf| {
                    mgf.element(Tag::OBJECT_IDENTIFIER, oid::MGF1);
                    mgf.sequence(|id| {
                        id.element(Tag::OBJECT_IDENTIFIER, mask_hash);
                        id.element(Tag::NULL, &[]);
                    });
                });
            });
            params.nested(Tag::explicit(2), |field| field.unsigned_integer(&[salt]));
        });
        identifier(oid::RSASSA_PSS, &writer.into_bytes())
    }

    #[test]
    fn known_identifiers() {
        // ECDSA without parameters, PKCS#1 with NULL or none, and the three PSS profiles.
        let null = [0x05, 0x00];
        let cases = [
            (
                identifier(oid::ECDSA_WITH_SHA256, &[]),
                SignatureAlgorithm::EcdsaSha256,
            ),
            (
                identifier(oid::ECDSA_WITH_SHA384, &[]),
                SignatureAlgorithm::EcdsaSha384,
            ),
            (
                identifier(oid::SHA256_WITH_RSA, &null),
                SignatureAlgorithm::RsaPkcs1Sha256,
            ),
            (
                identifier(oid::SHA384_WITH_RSA, &[]),
                SignatureAlgorithm::RsaPkcs1Sha384,
            ),
            (
                identifier(oid::SHA512_WITH_RSA, &null),
                SignatureAlgorithm::RsaPkcs1Sha512,
            ),
            (
                pss(oid::SHA256, oid::SHA256, 32),
                SignatureAlgorithm::RsaPssSha256,
            ),
            (
                pss(oid::SHA384, oid::SHA384, 48),
                SignatureAlgorithm::RsaPssSha384,
            ),
            (
                pss(oid::SHA512, oid::SHA512, 64),
                SignatureAlgorithm::RsaPssSha512,
            ),
        ];
        for (encoding, expected) in cases {
            assert_eq!(SignatureAlgorithm::from_der(&encoding), Ok(expected));
        }
    }

    #[test]
    fn other_parameters_are_refused() {
        let unsupported = Err(X509Error::UnsupportedSignatureAlgorithm);
        // Mutation: ECDSA with a NULL, PSS with a mismatched MGF1 hash, PSS with a 20-byte salt.
        assert_eq!(
            SignatureAlgorithm::from_der(&identifier(oid::ECDSA_WITH_SHA256, &[0x05, 0x00])),
            unsupported
        );
        assert_eq!(
            SignatureAlgorithm::from_der(&pss(oid::SHA256, oid::SHA384, 32)),
            unsupported
        );
        assert_eq!(
            SignatureAlgorithm::from_der(&pss(oid::SHA256, oid::SHA256, 20)),
            unsupported
        );
        // sha1WithRSAEncryption, 1.2.840.113549.1.1.5.
        assert_eq!(
            SignatureAlgorithm::from_der(&identifier(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
                &[0x05, 0x00]
            )),
            unsupported
        );
    }
}
