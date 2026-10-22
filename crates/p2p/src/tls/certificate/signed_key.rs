//! The libp2p public key extension: the host key, and its signature over the certificate key.

use sha2::{Digest, Sha256};

use super::{CertificateError, SubjectPublicKeyInfo};
use crate::{
    identity::{KeyType, Keypair, PublicKey},
    protobuf::ProtoMessage,
    tls::{
        EcdsaSigValue,
        der::{DerReader, DerWriter, Tag},
    },
};

/// The context string the host key signs before the certificate key, per the libp2p TLS spec.
const SIGNATURE_PREFIX: &[u8] = b"libp2p-tls-handshake:";

/// The content of the libp2p public key extension.
///
/// ```text
/// SignedKey ::= SEQUENCE {
///     publicKey  OCTET STRING,   -- the protobuf host public key
///     signature  OCTET STRING    -- host signature over prefix || certificate SPKI
/// }
/// ```
///
/// The host key never signs the certificate itself.
/// It signs the certificate key, so any host key type works with any certificate key type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedKey {
    /// The protobuf encoding of the host public key.
    public_key: Vec<u8>,
    /// The host signature, in the host scheme's own format.
    signature: Vec<u8>,
}

impl SignedKey {
    /// The host key's binding to a certificate key, given as its SubjectPublicKeyInfo DER.
    pub(crate) fn sign(host: &Keypair, certificate_key: &[u8]) -> Self {
        Self {
            public_key: host.public_key().encode(),
            signature: host.sign(&Self::message(certificate_key)).into_bytes(),
        }
    }

    /// Decodes the extension content.
    pub(crate) fn from_der(bytes: &[u8]) -> Result<Self, CertificateError> {
        let mut outer = DerReader::new(bytes);
        let mut body = outer.sequence()?;
        outer.finish()?;
        let public_key = body.octet_string()?.to_vec();
        let signature = body.octet_string()?.to_vec();
        body.finish()?;
        Ok(Self {
            public_key,
            signature,
        })
    }

    /// The extension content.
    pub(crate) fn to_der(&self) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.sequence(|body| {
            body.element(Tag::OCTET_STRING, &self.public_key);
            body.element(Tag::OCTET_STRING, &self.signature);
        });
        writer.into_bytes()
    }

    /// Checks the host signature over a certificate key and returns the host key.
    ///
    /// secp256k1 and ECDSA P-256 host keys are verified.
    /// Ethereum nodes use secp256k1; the other libp2p schemes are refused as unsupported.
    pub(crate) fn verify(&self, certificate_key: &[u8]) -> Result<PublicKey, CertificateError> {
        let host = PublicKey::decode(&self.public_key)?;
        let message = Self::message(certificate_key);
        let valid = match host.key_type {
            // ECDSA over SHA-256 with a DER signature, per the peer-ids spec.
            KeyType::Secp256k1 => host.verify(&message, &self.signature),
            // The key data is itself a SubjectPublicKeyInfo, per the peer-ids spec.
            KeyType::Ecdsa => {
                let key = SubjectPublicKeyInfo::from_der(&host.data)?;
                let hash: [u8; 32] = Sha256::digest(&message).into();
                EcdsaSigValue::from_der(&self.signature)
                    .is_ok_and(|value| key.key().verify(&hash, &value.signature()).is_ok())
            }
            KeyType::Ed25519 | KeyType::Rsa => {
                return Err(CertificateError::UnsupportedHostKey(host.key_type));
            }
        };
        if valid {
            Ok(host)
        } else {
            Err(CertificateError::InvalidHostSignature)
        }
    }

    /// The signed message: the prefix, then the certificate key's SubjectPublicKeyInfo DER.
    fn message(certificate_key: &[u8]) -> Vec<u8> {
        [SIGNATURE_PREFIX, certificate_key].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn signature_binds_the_certificate_key() {
        // Fixture state: a secp256k1 host signs the 3-byte stand-in key 01 02 03.
        let host = Keypair::from_secret_bytes(&[9; 32]).unwrap();
        let signed = SignedKey::sign(&host, &[1, 2, 3]);
        assert_eq!(SignedKey::from_der(&signed.to_der()), Ok(signed.clone()));
        assert_eq!(signed.verify(&[1, 2, 3]), Ok(host.public_key().clone()));

        // Mutation: another certificate key.
        assert_eq!(
            signed.verify(&[1, 2, 4]),
            Err(CertificateError::InvalidHostSignature)
        );
    }

    #[test]
    fn unsupported_host_keys_are_named() {
        // An Ed25519 host key from the peer-ids spec, with any signature.
        let signed = SignedKey {
            public_key: hex(
                "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e",
            ),
            signature: vec![0; 64],
        };
        assert_eq!(
            signed.verify(&[1]),
            Err(CertificateError::UnsupportedHostKey(KeyType::Ed25519))
        );
    }
}
