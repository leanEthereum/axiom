//! Subject public keys: decoding a SubjectPublicKeyInfo, and checking signatures made by it.

use axiom_crypto::{
    p256, p384,
    rsa::{RsaHash, RsaPublicKey},
};

use super::{SignatureAlgorithm, X509Error, oid};
use crate::{
    HashAlgorithm,
    der::{DerReader, Tag},
    ecdsa::EcdsaComponents,
};

/// Fewest modulus bits accepted for an RSA key.
///
/// NIST SP 800-131A, revision 2, section 3, disallows smaller moduli for signatures.
pub const MIN_RSA_BITS: usize = 2048;

/// A public key this stack verifies signatures with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// An ECDSA key on P-256.
    P256(p256::PublicKey),
    /// An ECDSA key on P-384.
    P384(p384::PublicKey),
    /// An RSA key.
    Rsa(RsaPublicKey),
}

impl PublicKey {
    /// Decodes one whole SubjectPublicKeyInfo.
    ///
    /// ```text
    /// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    /// ```
    ///
    /// EC keys name their curve, per RFC 5480, section 2.1.1.
    /// RSA keys carry NULL parameters and the RSAPublicKey structure, per RFC 3279, section 2.3.1.
    ///
    /// # Errors
    ///
    /// Fails on malformed DER, an unsupported algorithm or curve, or an invalid key.
    pub fn from_spki(der: &[u8]) -> Result<Self, X509Error> {
        let mut outer = DerReader::new(der);
        let mut info = outer.sequence()?;
        outer.finish()?;
        let mut algorithm = info.sequence()?;
        let key = info.bit_string()?;
        info.finish()?;

        let kind = algorithm.object_identifier()?;
        if kind == oid::EC_PUBLIC_KEY {
            let curve = algorithm.object_identifier()?;
            algorithm.finish()?;
            if curve == oid::PRIME256V1 {
                return p256::PublicKey::from_sec1_bytes(key)
                    .map(Self::P256)
                    .map_err(|_| X509Error::InvalidPublicKey);
            }
            if curve == oid::SECP384R1 {
                return p384::PublicKey::from_sec1_bytes(key)
                    .map(Self::P384)
                    .map_err(|_| X509Error::InvalidPublicKey);
            }
            return Err(X509Error::UnsupportedKeyAlgorithm);
        }
        if kind == oid::RSA_ENCRYPTION {
            // RFC 3279, section 2.3.1: the parameters field MUST be NULL.
            if !algorithm.element(Tag::NULL)?.is_empty() {
                return Err(X509Error::UnsupportedKeyAlgorithm);
            }
            algorithm.finish()?;
            let mut outer = DerReader::new(key);
            let mut fields = outer.sequence()?;
            outer.finish()?;
            let modulus = fields.unsigned_integer()?;
            let exponent = fields.unsigned_integer()?;
            fields.finish()?;
            return RsaPublicKey::new(modulus, exponent)
                .map(Self::Rsa)
                .map_err(|_| X509Error::InvalidPublicKey);
        }
        Err(X509Error::UnsupportedKeyAlgorithm)
    }

    /// Checks a signature over a message, under a certificate signature algorithm.
    ///
    /// A key verifies only the algorithms its type can make:
    ///
    /// - P-256 and P-384 keys verify ECDSA over SHA-256 or SHA-384;
    /// - RSA keys of 2048 bits or more verify PKCS#1 v1.5 and PSS over SHA-256, SHA-384 or SHA-512.
    ///
    /// Every input is public, so the check may take variable time.
    ///
    /// # Errors
    ///
    /// Fails on an incompatible algorithm, a short RSA key, a malformed signature, or a forgery.
    pub fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), X509Error> {
        let hash = algorithm.hash();
        let digest = hash.digest(message);
        match (self, algorithm) {
            (
                Self::P256(key),
                SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384,
            ) => {
                let compact = EcdsaComponents::from_der(signature)?.to_fixed::<64>()?;
                let signature = p256::Signature::from_bytes(&compact)
                    .map_err(|_| X509Error::MalformedSignature)?;
                // FIPS 186-4, section 6.4: a longer hash keeps its leftmost 256 bits.
                let mut truncated = [0_u8; 32];
                truncated.copy_from_slice(&digest[..32]);
                key.verify(&truncated, &signature)
                    .map_err(|_| X509Error::InvalidSignature)
            }
            (
                Self::P384(key),
                SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384,
            ) => {
                let compact = EcdsaComponents::from_der(signature)?.to_fixed::<96>()?;
                let signature = p384::Signature::from_bytes(&compact)
                    .map_err(|_| X509Error::MalformedSignature)?;
                key.verify(&digest, &signature)
                    .map_err(|_| X509Error::InvalidSignature)
            }
            (
                Self::Rsa(key),
                SignatureAlgorithm::RsaPkcs1Sha256
                | SignatureAlgorithm::RsaPkcs1Sha384
                | SignatureAlgorithm::RsaPkcs1Sha512,
            ) => {
                Self::check_rsa_size(key)?;
                key.verify_pkcs1v15(Self::rsa_hash(hash), &digest, signature)
                    .map_err(|_| X509Error::InvalidSignature)
            }
            (
                Self::Rsa(key),
                SignatureAlgorithm::RsaPssSha256
                | SignatureAlgorithm::RsaPssSha384
                | SignatureAlgorithm::RsaPssSha512,
            ) => {
                Self::check_rsa_size(key)?;
                // RFC 8446, section 4.2.3, and RFC 4055: the salt is as long as the hash.
                key.verify_pss(Self::rsa_hash(hash), &digest, signature, hash.output_len())
                    .map_err(|_| X509Error::InvalidSignature)
            }
            _ => Err(X509Error::IncompatibleKey),
        }
    }

    /// Refuses an RSA modulus below the minimum size.
    fn check_rsa_size(key: &RsaPublicKey) -> Result<(), X509Error> {
        let bits = key.bits();
        if bits < MIN_RSA_BITS {
            return Err(X509Error::RsaKeyTooSmall {
                bits,
                min: MIN_RSA_BITS,
            });
        }
        Ok(())
    }

    /// The RSA module's name for a hash.
    const fn rsa_hash(hash: HashAlgorithm) -> RsaHash {
        match hash {
            HashAlgorithm::Sha256 => RsaHash::Sha256,
            HashAlgorithm::Sha384 => RsaHash::Sha384,
            HashAlgorithm::Sha512 => RsaHash::Sha512,
        }
    }
}
