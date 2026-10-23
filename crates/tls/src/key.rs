//! A server's identity: its certificate chain and the private key that signs for it.
//!
//! # Overview
//!
//! Keys load from the PEM forms that common tools write:
//!
//! - PRIVATE KEY: PKCS#8, RFC 5208, holding either key type;
//! - EC PRIVATE KEY: SEC 1, RFC 5915;
//! - RSA PRIVATE KEY: PKCS#1, RFC 8017, appendix A.1.2.
//!
//! P-256 and RSA keys sign; other curves are refused at load.
//!
//! # Timing
//!
//! Signing runs in constant time for both key types.
//! Loading parses a local file once, branching only on its structure.

use std::fmt;

use axiom_crypto::{
    p256,
    rsa::{RsaHash, RsaPrivateKey},
};
use thiserror::Error;

use crate::{
    EcdsaSigValue, HashAlgorithm, PemBlock, PemError, SignatureScheme,
    der::{DerError, DerReader, Tag},
    x509::{Certificate, PublicKey, X509Error, oid},
};

/// The PEM label of a certificate.
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

/// Bytes of a P-256 private scalar.
const P256_SCALAR_LEN: usize = 32;

/// A private key or certificate chain that cannot serve as a TLS identity.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The file is not PEM.
    #[error("{0}")]
    Pem(#[from] PemError),

    /// The file holds no private key block.
    #[error("no private key in the file")]
    NoKey,

    /// The file holds no certificate.
    #[error("no certificate in the file")]
    NoCertificate,

    /// A key or certificate structure is malformed.
    #[error("malformed key or certificate: {0}")]
    Malformed(#[from] X509Error),

    /// The key's algorithm or curve is not one this stack signs with.
    #[error("unsupported private key algorithm")]
    UnsupportedAlgorithm,

    /// The key's numbers are inconsistent or out of range.
    #[error("invalid private key")]
    InvalidKey,

    /// The certificate names another public key than the private key's.
    #[error("certificate does not match the private key")]
    KeyMismatch,

    /// A signature failed its own check, a sign of a computation fault.
    #[error("signature failed its consistency check")]
    SigningFailed,
}

impl From<DerError> for KeyError {
    fn from(error: DerError) -> Self {
        Self::Malformed(error.into())
    }
}

/// A private key this stack signs handshakes with.
pub enum SigningKey {
    /// An ECDSA key on P-256.
    EcdsaP256(p256::SecretKey),
    /// An RSA key.
    Rsa(Box<RsaPrivateKey>),
}

impl SigningKey {
    /// Reads the first private key block of a PEM file.
    ///
    /// # Errors
    ///
    /// Fails on a file without a key block, a malformed key, or an unsupported algorithm.
    pub fn from_pem(file: &[u8]) -> Result<Self, KeyError> {
        for block in PemBlock::parse_all(file)? {
            match block.label.as_str() {
                "PRIVATE KEY" => return Self::from_pkcs8(&block.der),
                "EC PRIVATE KEY" => return Self::from_sec1(&block.der, None),
                "RSA PRIVATE KEY" => return Self::from_pkcs1(&block.der),
                _ => {}
            }
        }
        Err(KeyError::NoKey)
    }

    /// Decodes a PKCS#8 PrivateKeyInfo, per RFC 5208, section 5, and RFC 5958, section 2.
    ///
    /// ```text
    /// PrivateKeyInfo ::= SEQUENCE { version INTEGER, privateKeyAlgorithm AlgorithmIdentifier,
    ///                               privateKey OCTET STRING, attributes [0] OPTIONAL, publicKey [1] OPTIONAL }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails on malformed DER, an unsupported algorithm, or an invalid key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        let mut outer = DerReader::new(der);
        let mut info = outer.sequence()?;
        outer.finish()?;
        // Version 0 is PKCS#8; version 1 adds the optional public key of RFC 5958.
        if info.small_integer()? > 1 {
            return Err(KeyError::UnsupportedAlgorithm);
        }
        let mut algorithm = info.sequence()?;
        let private_key = info.octet_string()?;
        let kind = algorithm.object_identifier()?;
        if kind == oid::EC_PUBLIC_KEY {
            let curve = algorithm.object_identifier()?;
            algorithm.finish()?;
            return Self::from_sec1(private_key, Some(curve));
        }
        if kind == oid::RSA_ENCRYPTION {
            if !algorithm.element(Tag::NULL)?.is_empty() {
                return Err(KeyError::UnsupportedAlgorithm);
            }
            algorithm.finish()?;
            return Self::from_pkcs1(private_key);
        }
        Err(KeyError::UnsupportedAlgorithm)
    }

    /// Decodes a SEC 1 ECPrivateKey, per RFC 5915, section 3.
    ///
    /// ```text
    /// ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET STRING,
    ///                             parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
    /// ```
    ///
    /// The curve comes from the PKCS#8 wrapper or the parameters field; at least one must name P-256.
    fn from_sec1(der: &[u8], wrapper_curve: Option<&[u8]>) -> Result<Self, KeyError> {
        let mut outer = DerReader::new(der);
        let mut fields = outer.sequence()?;
        outer.finish()?;
        if fields.small_integer()? != 1 {
            return Err(KeyError::InvalidKey);
        }
        let scalar = fields.octet_string()?;
        let inner_curve = match fields.optional(Tag::explicit(0))? {
            Some(content) => {
                let mut parameters = DerReader::new(content);
                let curve = parameters.object_identifier()?;
                parameters.finish()?;
                Some(curve)
            }
            None => None,
        };
        let declared_key = match fields.optional(Tag::explicit(1))? {
            Some(content) => {
                let mut wrapper = DerReader::new(content);
                let point = wrapper.bit_string()?;
                wrapper.finish()?;
                Some(point)
            }
            None => None,
        };
        fields.finish()?;

        let curve = match (wrapper_curve, inner_curve) {
            (Some(outer), Some(inner)) if outer != inner => return Err(KeyError::InvalidKey),
            (Some(curve), _) | (None, Some(curve)) => curve,
            (None, None) => return Err(KeyError::UnsupportedAlgorithm),
        };
        if curve != oid::PRIME256V1 {
            return Err(KeyError::UnsupportedAlgorithm);
        }
        let scalar: &[u8; P256_SCALAR_LEN] = scalar.try_into().map_err(|_| KeyError::InvalidKey)?;
        let key = p256::SecretKey::from_bytes(scalar).map_err(|_| KeyError::InvalidKey)?;
        // A stated public key must be the one the scalar gives.
        if let Some(point) = declared_key
            && point != key.public_key().to_uncompressed()
            && point != key.public_key().to_compressed()
        {
            return Err(KeyError::InvalidKey);
        }
        Ok(Self::EcdsaP256(key))
    }

    /// Decodes a two-prime PKCS#1 RSAPrivateKey, per RFC 8017, appendix A.1.2.
    fn from_pkcs1(der: &[u8]) -> Result<Self, KeyError> {
        let mut outer = DerReader::new(der);
        let mut fields = outer.sequence()?;
        outer.finish()?;
        // Version 1 marks a multi-prime key, which this stack does not load.
        if fields.small_integer()? != 0 {
            return Err(KeyError::UnsupportedAlgorithm);
        }
        let mut numbers = [&[][..]; 8];
        for number in &mut numbers {
            *number = fields.unsigned_integer()?;
        }
        fields.finish()?;
        let [
            modulus,
            public,
            private,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        ] = numbers;
        RsaPrivateKey::from_components(
            modulus,
            public,
            private,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        )
        .map(|key| Self::Rsa(Box::new(key)))
        .map_err(|_| KeyError::InvalidKey)
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::EcdsaP256(key) => PublicKey::P256(key.public_key()),
            Self::Rsa(key) => PublicKey::Rsa(key.public_key().clone()),
        }
    }

    /// The first scheme of a peer's list this key can sign with in TLS 1.3.
    #[must_use]
    pub fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<SignatureScheme> {
        let ours: &[SignatureScheme] = match self {
            Self::EcdsaP256(_) => &[SignatureScheme::ECDSA_SECP256R1_SHA256],
            Self::Rsa(_) => &[
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA384,
                SignatureScheme::RSA_PSS_RSAE_SHA512,
            ],
        };
        ours.iter().copied().find(|scheme| offered.contains(scheme))
    }

    /// Signs a message under a scheme this key supports.
    ///
    /// ECDSA nonces follow RFC 6979, so only RSA-PSS reads the salt; it takes as many bytes as the hash.
    ///
    /// # Errors
    ///
    /// Fails on a scheme this key cannot use, or a signature that fails its fault check.
    pub fn sign(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        salt: &[u8; 64],
    ) -> Result<Vec<u8>, KeyError> {
        match (self, scheme) {
            (Self::EcdsaP256(key), SignatureScheme::ECDSA_SECP256R1_SHA256) => {
                let digest = HashAlgorithm::Sha256.digest(message);
                let mut hash = [0_u8; 32];
                hash.copy_from_slice(&digest);
                Ok(EcdsaSigValue::from(key.sign(&hash)).to_der())
            }
            (Self::Rsa(key), _) => {
                let (hash, rsa_hash) = match scheme {
                    SignatureScheme::RSA_PSS_RSAE_SHA256 => {
                        (HashAlgorithm::Sha256, RsaHash::Sha256)
                    }
                    SignatureScheme::RSA_PSS_RSAE_SHA384 => {
                        (HashAlgorithm::Sha384, RsaHash::Sha384)
                    }
                    SignatureScheme::RSA_PSS_RSAE_SHA512 => {
                        (HashAlgorithm::Sha512, RsaHash::Sha512)
                    }
                    _ => return Err(KeyError::UnsupportedAlgorithm),
                };
                let digest = hash.digest(message);
                key.sign_pss(rsa_hash, &digest, &salt[..hash.output_len()])
                    .map_err(|_| KeyError::SigningFailed)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is secret: only its type prints.
        let kind = match self {
            Self::EcdsaP256(_) => "EcdsaP256",
            Self::Rsa(_) => "Rsa",
        };
        f.debug_tuple("SigningKey").field(&kind).finish()
    }
}

/// A certificate chain and the private key of its first certificate.
#[derive(Debug)]
pub struct CertifiedKey {
    /// The DER certificates, the end-entity first.
    chain: Vec<Vec<u8>>,
    /// The key the first certificate names.
    key: SigningKey,
}

impl CertifiedKey {
    /// Pairs a chain with its key, checking the first certificate names that key.
    ///
    /// # Errors
    ///
    /// Fails on an empty chain, a malformed first certificate, or a key mismatch.
    pub fn new(chain: Vec<Vec<u8>>, key: SigningKey) -> Result<Self, KeyError> {
        let leaf = chain.first().ok_or(KeyError::NoCertificate)?;
        let named = Certificate::parse(leaf)?.public_key()?;
        if named != key.public_key() {
            return Err(KeyError::KeyMismatch);
        }
        Ok(Self { chain, key })
    }

    /// Reads a PEM certificate chain and a PEM private key.
    ///
    /// # Errors
    ///
    /// Fails on unreadable PEM, no certificate, an unusable key, or a mismatch.
    pub fn from_pem(certificates: &[u8], key: &[u8]) -> Result<Self, KeyError> {
        let chain = PemBlock::parse_all(certificates)?
            .into_iter()
            .filter(|block| block.label == CERTIFICATE_LABEL)
            .map(|block| block.der)
            .collect();
        Self::new(chain, SigningKey::from_pem(key)?)
    }

    /// The DER certificates, the end-entity first.
    #[must_use]
    pub fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    /// The private key.
    #[must_use]
    pub const fn key(&self) -> &SigningKey {
        &self.key
    }
}
