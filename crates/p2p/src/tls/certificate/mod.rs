//! The libp2p certificate: a self-signed X.509 certificate that carries the host key.
//!
//! # Overview
//!
//! A peer proves its identity without its host key ever signing a certificate.
//!
//! 1. It draws an ephemeral P-256 certificate key.
//! 2. Its host key signs "libp2p-tls-handshake:" followed by that key's SubjectPublicKeyInfo.
//! 3. The host key and that signature go into an extension of a certificate the P-256 key signs.
//! 4. TLS then proves possession of the P-256 key through the CertificateVerify message.
//!
//! The verifier checks the certificate's shape, its self-signature, its validity window, and the host signature.
//! The peer identifier then follows from the host key.
//! See the libp2p TLS spec, and RFC 5280 for the certificate format.
//!
//! # Timing
//!
//! Certificates and signatures are public, so parsing and verification may take variable time.
//! Only signing with the certificate key touches a secret, and it runs in constant time.

mod builder;
mod error;
mod parse;
mod signed_key;
mod spki;

pub(crate) use builder::CertificateBuilder;
pub use error::CertificateError;
pub(crate) use parse::ParsedCertificate;
pub(crate) use signed_key::SignedKey;
pub(crate) use spki::SubjectPublicKeyInfo;

/// The OID 1.3.6.1.4.1.53594.1.1 of the libp2p public key extension, assigned by IANA.
const LIBP2P_EXTENSION_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xa2, 0x5a, 0x01, 0x01];

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::SecretKey;
    use axiom_tls::{
        der::{DerError, DerWriter, Tag, Timestamp},
        x509::X509Error,
    };

    use super::*;
    use crate::identity::Keypair;

    /// A builder over a fixed certificate key.
    fn key() -> SecretKey {
        SecretKey::from_bytes(&[3; 32]).unwrap()
    }

    /// The fixed host key pair.
    fn host() -> Keypair {
        Keypair::from_secret_bytes(&[4; 32]).unwrap()
    }

    /// A certificate whose extension list the closure writes, signed properly.
    fn with_extensions(list: impl FnOnce(&mut DerWriter, &[u8])) -> Vec<u8> {
        let key = key();
        let builder = CertificateBuilder::new(&key);
        let signed_key = SignedKey::sign(&host(), builder.key_info()).to_der();
        builder.sign(|fields| {
            builder.fields(fields, |rest| {
                CertificateBuilder::extensions(rest, |extensions| list(extensions, &signed_key));
            });
        })
    }

    /// Parses and checks a certificate the way a handshake does, at a fixed instant in 2026.
    fn check(der: &[u8]) -> Result<(), CertificateError> {
        let certificate = ParsedCertificate::parse(der)?;
        certificate.verify_signature()?;
        certificate.check_validity(Timestamp::from_unix_secs(1_792_000_000))?;
        SignedKey::from_der(certificate.signed_key())?.verify(certificate.key_encoding())?;
        Ok(())
    }

    #[test]
    fn generated_certificate_passes_every_check() {
        let key = key();
        let der = CertificateBuilder::new(&key).build(&host());
        assert_eq!(check(&der), Ok(()));

        // The window runs from the epoch to the last second of 9999.
        let certificate = ParsedCertificate::parse(&der).unwrap();
        assert_eq!(certificate.key(), &key.public_key());
        assert_eq!(
            certificate.check_validity(Timestamp::from_unix_secs(253_402_300_800)),
            Err(CertificateError::Expired {
                not_after: 253_402_300_799,
                now: 253_402_300_800
            })
        );
    }

    #[test]
    fn extension_rules() {
        // Mutation: no libp2p extension, only an unknown non-critical one.
        let unknown = [0x2a, 0x03];
        let der =
            with_extensions(|list, _| CertificateBuilder::extension(list, &unknown, false, &[]));
        assert_eq!(check(&der), Err(CertificateError::MissingExtension));

        // An unknown non-critical extension beside the libp2p one is ignored.
        let der = with_extensions(|list, signed| {
            CertificateBuilder::extension(list, &unknown, false, &[]);
            CertificateBuilder::extension(list, LIBP2P_EXTENSION_OID, false, signed);
        });
        assert_eq!(check(&der), Ok(()));

        // The libp2p extension may itself be critical.
        let der = with_extensions(|list, signed| {
            CertificateBuilder::extension(list, LIBP2P_EXTENSION_OID, true, signed);
        });
        assert_eq!(check(&der), Ok(()));

        // Mutation: the unknown extension is critical.
        let der = with_extensions(|list, signed| {
            CertificateBuilder::extension(list, LIBP2P_EXTENSION_OID, false, signed);
            CertificateBuilder::extension(list, &unknown, true, &[]);
        });
        assert_eq!(check(&der), Err(CertificateError::UnknownCriticalExtension));

        // Mutation: the libp2p extension twice.
        let der = with_extensions(|list, signed| {
            CertificateBuilder::extension(list, LIBP2P_EXTENSION_OID, false, signed);
            CertificateBuilder::extension(list, LIBP2P_EXTENSION_OID, false, signed);
        });
        assert_eq!(
            check(&der),
            Err(CertificateError::X509(X509Error::DuplicateExtension))
        );

        // Mutation: a critical flag written as an explicit false.
        let der = with_extensions(|list, signed| {
            list.sequence(|extension| {
                extension.element(Tag::OBJECT_IDENTIFIER, LIBP2P_EXTENSION_OID);
                extension.boolean(false);
                extension.element(Tag::OCTET_STRING, signed);
            });
        });
        assert_eq!(
            check(&der),
            Err(CertificateError::X509(X509Error::ExplicitDefault))
        );
    }

    #[test]
    fn profile_rules() {
        let key = key();
        let builder = CertificateBuilder::new(&key);

        // Mutation: no extensions field at all.
        let der = builder.sign(|fields| builder.fields(fields, |_| {}));
        assert_eq!(check(&der), Err(CertificateError::MissingExtension));

        // Mutation: a subject unique identifier, the IMPLICIT [2] BIT STRING 00 aa.
        let der = builder.sign(|fields| {
            builder.fields(fields, |rest| rest.element(Tag::implicit(2), &[0x00, 0xaa]));
        });
        assert_eq!(check(&der), Err(CertificateError::UniqueIdentifier));

        // Mutation: version 1 in place of 3, the bytes a0 03 02 01 02 near the start.
        let mut der = builder.build(&host());
        let at = der
            .windows(5)
            .position(|window| window == [0xa0, 0x03, 0x02, 0x01, 0x02])
            .unwrap();
        der[at + 4] = 0x01;
        assert_eq!(
            check(&der),
            Err(CertificateError::X509(X509Error::UnsupportedVersion(1)))
        );

        // Mutation: the last byte of s, the last byte of the certificate.
        let mut der = builder.build(&host());
        let last = der.len() - 1;
        der[last] ^= 1;
        assert_eq!(check(&der), Err(CertificateError::InvalidSelfSignature));

        // Mutation: one byte of the signed part, the last byte of the organization name.
        let mut der = builder.build(&host());
        let at = der
            .windows(6)
            .position(|window| window == b"libp2p")
            .unwrap();
        der[at + 5] = b'q';
        assert_eq!(check(&der), Err(CertificateError::InvalidSelfSignature));

        // Mutation: a trailing byte after the certificate.
        let mut der = builder.build(&host());
        der.push(0);
        assert_eq!(
            check(&der),
            Err(CertificateError::X509(X509Error::Der(
                DerError::TrailingBytes { count: 1 }
            )))
        );
    }
}
