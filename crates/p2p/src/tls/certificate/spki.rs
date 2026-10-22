//! The SubjectPublicKeyInfo of a P-256 key, per RFC 5480, section 2.

use axiom_crypto::p256::PublicKey;

use super::{CertificateError, EC_PUBLIC_KEY_OID, PRIME256V1_OID};
use crate::tls::der::{DerReader, DerWriter, Tag};

/// A P-256 public key in the X.509 SubjectPublicKeyInfo form.
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  SEQUENCE { id-ecPublicKey, prime256v1 },
///     subjectPublicKey  BIT STRING   -- the SEC 1 point
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubjectPublicKeyInfo(PublicKey);

impl SubjectPublicKeyInfo {
    /// Wraps a key.
    pub(crate) const fn new(key: PublicKey) -> Self {
        Self(key)
    }

    /// The key.
    pub(crate) const fn key(&self) -> &PublicKey {
        &self.0
    }

    /// Decodes one whole SubjectPublicKeyInfo.
    ///
    /// Only an EC key on the named curve P-256 is accepted, in either SEC 1 point form.
    pub(crate) fn from_der(bytes: &[u8]) -> Result<Self, CertificateError> {
        let mut outer = DerReader::new(bytes);
        let mut info = outer.sequence()?;
        outer.finish()?;

        // RFC 5480, section 2.1.1: the parameters name the curve, and nothing else is allowed.
        let mut algorithm = info.sequence()?;
        let key_type = algorithm.object_identifier()?;
        let curve = algorithm.object_identifier()?;
        algorithm.finish()?;
        if key_type != EC_PUBLIC_KEY_OID || curve != PRIME256V1_OID {
            return Err(CertificateError::UnsupportedKeyAlgorithm);
        }

        let point = info.bit_string()?;
        info.finish()?;
        Ok(Self(PublicKey::from_sec1_bytes(point)?))
    }

    /// The DER encoding, with the point uncompressed as RFC 5480 recommends.
    pub(crate) fn to_der(self) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.sequence(|info| {
            info.sequence(|algorithm| {
                algorithm.element(Tag::OBJECT_IDENTIFIER, EC_PUBLIC_KEY_OID);
                algorithm.element(Tag::OBJECT_IDENTIFIER, PRIME256V1_OID);
            });
            info.bit_string(&self.0.to_uncompressed());
        });
        writer.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::{P256Error, SecretKey};

    use super::*;
    use crate::testing::hex;

    /// The certificate key of the libp2p TLS spec test vectors.
    const SPEC_KEY: &str = concat!(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132",
        "721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd",
        "37e381569e"
    );

    #[test]
    fn spec_key_round_trips() {
        // 91 bytes: a 19-byte algorithm, then a 66-byte bit string holding 0x04 || x || y.
        let der = hex(SPEC_KEY);
        let info = SubjectPublicKeyInfo::from_der(&der).unwrap();
        assert_eq!(info.key().to_uncompressed()[..3], [0x04, 0x0c, 0x90]);
        assert_eq!(info.to_der(), der);
    }

    #[test]
    fn other_curves_and_bad_points_are_refused() {
        // Mutation: the curve OID ends in 0x08 instead of 0x07.
        let mut der = hex(SPEC_KEY);
        der[22] = 0x08;
        assert_eq!(
            SubjectPublicKeyInfo::from_der(&der),
            Err(CertificateError::UnsupportedKeyAlgorithm)
        );

        // Mutation: the last coordinate byte, which moves the point off the curve.
        let mut der = hex(SPEC_KEY);
        let last = der.len() - 1;
        der[last] ^= 1;
        assert_eq!(
            SubjectPublicKeyInfo::from_der(&der),
            Err(CertificateError::P256(P256Error::InvalidPublicKey))
        );

        // A fresh key survives the round trip.
        let key = SecretKey::from_bytes(&[5; 32]).unwrap().public_key();
        let info = SubjectPublicKeyInfo::new(key);
        assert_eq!(SubjectPublicKeyInfo::from_der(&info.to_der()), Ok(info));
    }
}
