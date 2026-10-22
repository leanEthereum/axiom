//! Writing and self-signing a libp2p certificate.

use axiom_crypto::p256::SecretKey;
use axiom_tls::{
    EcdsaSigValue,
    der::{DerWriter, Tag, Timestamp},
    x509::oid,
};
use sha2::{Digest, Sha256};

use super::{LIBP2P_EXTENSION_OID, SignedKey, SubjectPublicKeyInfo};
use crate::identity::Keypair;

/// The version field value of an X.509 v3 certificate.
const VERSION_3: &[u8] = &[2];

/// The issuer and subject organization; nothing reads it, but RFC 5280 wants a non-empty issuer.
const ORGANIZATION: &[u8] = b"libp2p";

/// Bytes of the serial number: 64 bits, well under the 20 bytes RFC 5280 allows.
const SERIAL_LEN: usize = 8;

/// Writes the self-signed certificate of one certificate key.
#[derive(Debug)]
pub(crate) struct CertificateBuilder<'a> {
    /// The certificate key, which signs the certificate.
    key: &'a SecretKey,
    /// The certificate key's SubjectPublicKeyInfo DER.
    key_info: Vec<u8>,
}

impl<'a> CertificateBuilder<'a> {
    /// A builder for the certificate of a key.
    pub(crate) fn new(key: &'a SecretKey) -> Self {
        Self {
            key,
            key_info: SubjectPublicKeyInfo::new(key.public_key()).to_der(),
        }
    }

    /// The certificate binding a host key, with the libp2p extension only.
    ///
    /// The validity window runs from the epoch to 9999-12-31 23:59:59 UTC.
    /// RFC 5280, section 4.1.2.5, gives the end date as "no well-defined expiration".
    /// The certificate thus never depends on a clock, and every honest verifier accepts it.
    pub(crate) fn build(&self, host: &Keypair) -> Vec<u8> {
        let signed_key = SignedKey::sign(host, &self.key_info).to_der();
        self.sign(|fields| {
            self.fields(fields, |rest| {
                Self::extensions(rest, |list| {
                    Self::extension(list, LIBP2P_EXTENSION_OID, false, &signed_key);
                });
            });
        })
    }

    /// The certificate key's SubjectPublicKeyInfo DER.
    #[cfg(test)]
    pub(crate) fn key_info(&self) -> &[u8] {
        &self.key_info
    }

    /// Wraps the signed part, then appends the algorithm and the signature.
    pub(crate) fn sign(&self, fields: impl FnOnce(&mut DerWriter)) -> Vec<u8> {
        let mut tbs = DerWriter::new();
        tbs.sequence(fields);
        let tbs = tbs.into_bytes();
        let hash: [u8; 32] = Sha256::digest(&tbs).into();
        let signature = EcdsaSigValue::from(self.key.sign(&hash)).to_der();

        let mut certificate = DerWriter::new();
        certificate.nested(Tag::SEQUENCE, |body| {
            // The signed part is already encoded, so it is copied whole.
            body.encoded(&tbs);
            Self::algorithm(body);
            body.bit_string(&signature);
        });
        certificate.into_bytes()
    }

    /// Writes the fields of the signed part up to the key, then whatever the closure adds.
    pub(crate) fn fields(&self, fields: &mut DerWriter, rest: impl FnOnce(&mut DerWriter)) {
        fields.nested(Tag::explicit(0), |version| {
            version.unsigned_integer(VERSION_3);
        });
        fields.unsigned_integer(&self.serial());
        Self::algorithm(fields);
        Self::name(fields);
        fields.sequence(|validity| {
            Timestamp::from_unix_secs(0).write(validity);
            Timestamp::from_civil(9999, 12, 31, 86_399).write(validity);
        });
        Self::name(fields);
        fields.encoded(&self.key_info);
        rest(fields);
    }

    /// Writes the extensions field, whose list the closure fills.
    pub(crate) fn extensions(fields: &mut DerWriter, list: impl FnOnce(&mut DerWriter)) {
        fields.nested(Tag::explicit(3), |wrapper| wrapper.sequence(list));
    }

    /// Writes one extension; DER leaves a false critical flag out.
    pub(crate) fn extension(list: &mut DerWriter, oid: &[u8], critical: bool, value: &[u8]) {
        list.sequence(|extension| {
            extension.element(Tag::OBJECT_IDENTIFIER, oid);
            if critical {
                extension.boolean(true);
            }
            extension.element(Tag::OCTET_STRING, value);
        });
    }

    /// A positive serial number derived from the public key, so no secret shapes it.
    fn serial(&self) -> [u8; SERIAL_LEN] {
        let digest = Sha256::digest(&self.key_info);
        let mut serial = [0_u8; SERIAL_LEN];
        serial.copy_from_slice(&digest[..SERIAL_LEN]);
        // Clear the sign bit and set the next one: positive and never zero.
        serial[0] = (serial[0] & 0x7f) | 0x40;
        serial
    }

    /// Writes the ecdsa-with-SHA256 algorithm identifier, without parameters.
    fn algorithm(writer: &mut DerWriter) {
        writer.sequence(|algorithm| {
            algorithm.element(Tag::OBJECT_IDENTIFIER, oid::ECDSA_WITH_SHA256);
        });
    }

    /// Writes the name O=libp2p.
    fn name(writer: &mut DerWriter) {
        writer.sequence(|name| {
            name.nested(Tag::SET, |set| {
                set.sequence(|attribute| {
                    attribute.element(Tag::OBJECT_IDENTIFIER, oid::ORGANIZATION_NAME);
                    attribute.element(Tag::UTF8_STRING, ORGANIZATION);
                });
            });
        });
    }
}
