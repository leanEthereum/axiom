//! Handshake signature schemes: what a peer signs the transcript or key exchange with.

use crate::x509::{PublicKey, SignatureAlgorithm, X509Error};

/// A TLS signature scheme code point, per RFC 8446, section 4.2.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    /// rsa_pkcs1_sha256, TLS 1.2 only in handshake signatures.
    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    /// rsa_pkcs1_sha384, TLS 1.2 only in handshake signatures.
    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    /// rsa_pkcs1_sha512, TLS 1.2 only in handshake signatures.
    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    /// ecdsa_secp256r1_sha256.
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    /// ecdsa_secp384r1_sha384.
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    /// rsa_pss_rsae_sha256: PSS with an rsaEncryption key.
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    /// rsa_pss_rsae_sha384.
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    /// rsa_pss_rsae_sha512.
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);

    /// The schemes a web client offers, in preference order.
    ///
    /// They cover the keys public servers hold: P-256, P-384, and RSA.
    /// The PKCS#1 schemes serve TLS 1.2 key exchanges, and certificate signatures in either version.
    pub const WEB: [Self; 8] = [
        Self::ECDSA_SECP256R1_SHA256,
        Self::ECDSA_SECP384R1_SHA384,
        Self::RSA_PSS_RSAE_SHA256,
        Self::RSA_PSS_RSAE_SHA384,
        Self::RSA_PSS_RSAE_SHA512,
        Self::RSA_PKCS1_SHA256,
        Self::RSA_PKCS1_SHA384,
        Self::RSA_PKCS1_SHA512,
    ];

    /// The certificate algorithm with the same hash and padding.
    #[must_use]
    pub const fn algorithm(self) -> Option<SignatureAlgorithm> {
        Some(match self {
            Self::RSA_PKCS1_SHA256 => SignatureAlgorithm::RsaPkcs1Sha256,
            Self::RSA_PKCS1_SHA384 => SignatureAlgorithm::RsaPkcs1Sha384,
            Self::RSA_PKCS1_SHA512 => SignatureAlgorithm::RsaPkcs1Sha512,
            Self::ECDSA_SECP256R1_SHA256 => SignatureAlgorithm::EcdsaSha256,
            Self::ECDSA_SECP384R1_SHA384 => SignatureAlgorithm::EcdsaSha384,
            Self::RSA_PSS_RSAE_SHA256 => SignatureAlgorithm::RsaPssSha256,
            Self::RSA_PSS_RSAE_SHA384 => SignatureAlgorithm::RsaPssSha384,
            Self::RSA_PSS_RSAE_SHA512 => SignatureAlgorithm::RsaPssSha512,
            _ => return None,
        })
    }

    /// Whether TLS 1.3 allows the scheme in a CertificateVerify.
    ///
    /// RFC 8446, section 4.4.3: PKCS#1 v1.5 is for certificates only.
    #[must_use]
    pub const fn allowed_in_tls13(self) -> bool {
        !matches!(
            self,
            Self::RSA_PKCS1_SHA256 | Self::RSA_PKCS1_SHA384 | Self::RSA_PKCS1_SHA512
        )
    }

    /// Whether a key can make signatures of this scheme in TLS 1.3.
    ///
    /// The ECDSA schemes of TLS 1.3 also fix the curve.
    #[must_use]
    pub const fn fits_tls13(self, key: &PublicKey) -> bool {
        matches!(
            (self, key),
            (Self::ECDSA_SECP256R1_SHA256, PublicKey::P256(_))
                | (Self::ECDSA_SECP384R1_SHA384, PublicKey::P384(_))
                | (
                    Self::RSA_PSS_RSAE_SHA256
                        | Self::RSA_PSS_RSAE_SHA384
                        | Self::RSA_PSS_RSAE_SHA512,
                    PublicKey::Rsa(_)
                )
        )
    }

    /// Checks a handshake signature over a message.
    ///
    /// In TLS 1.3 the scheme must fit the key, curve included.
    /// In TLS 1.2 an ECDSA scheme names only the hash, so any supported curve may sign.
    ///
    /// # Errors
    ///
    /// Fails on an unknown or ill-fitting scheme, or a signature that does not verify.
    pub fn verify(
        self,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
        tls13: bool,
    ) -> Result<(), X509Error> {
        let algorithm = self
            .algorithm()
            .ok_or(X509Error::UnsupportedSignatureAlgorithm)?;
        if tls13 && (!self.allowed_in_tls13() || !self.fits_tls13(key)) {
            return Err(X509Error::IncompatibleKey);
        }
        key.verify(algorithm, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::SecretKey;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::EcdsaSigValue;

    #[test]
    fn tls13_binds_curve_and_padding() {
        // Fixture state: a P-256 key signs "m" under SHA-256.
        let secret = SecretKey::from_bytes(&[7; 32]).unwrap();
        let key = PublicKey::P256(secret.public_key());
        let hash: [u8; 32] = Sha256::digest(b"m").into();
        let signature = EcdsaSigValue::from(secret.sign(&hash)).to_der();

        let scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
        assert_eq!(scheme.verify(&key, b"m", &signature, true), Ok(()));
        assert_eq!(
            scheme.verify(&key, b"n", &signature, true),
            Err(X509Error::InvalidSignature)
        );

        // Mutation: the P-384 scheme names SHA-384 and the wrong curve for TLS 1.3.
        assert_eq!(
            SignatureScheme::ECDSA_SECP384R1_SHA384.verify(&key, b"m", &signature, true),
            Err(X509Error::IncompatibleKey)
        );
        // An unknown code point.
        assert_eq!(
            SignatureScheme(0x0807).verify(&key, b"m", &signature, false),
            Err(X509Error::UnsupportedSignatureAlgorithm)
        );
        assert!(!SignatureScheme::RSA_PKCS1_SHA256.allowed_in_tls13());
    }
}
