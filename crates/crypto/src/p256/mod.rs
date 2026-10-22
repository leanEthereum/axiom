//! ECDSA over NIST P-256, the curve of TLS certificate keys.
//!
//! Placeholder interface: every operation refuses until the implementation lands.

use thiserror::Error;

/// A malformed key or signature, or a signature that does not check out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum P256Error {
    /// A secret key is zero or not below the group order.
    #[error("secret key is zero or not below the group order")]
    InvalidSecretKey,

    /// A public key encoding has a wrong prefix, or its point is off the curve.
    #[error("invalid public key encoding")]
    InvalidPublicKey,

    /// A public key encoding is neither 33 nor 65 bytes long.
    #[error("public key encoding of {0} bytes is neither 33 nor 65")]
    InvalidPublicKeyLength(usize),

    /// A signature component is zero or not below the group order.
    #[error("signature component at byte {offset} is zero or not below the group order")]
    InvalidSignature {
        /// Byte offset of the component in the compact form: 0 for r, 32 for s.
        offset: usize,
    },

    /// A signature does not verify under the key.
    #[error("signature does not verify")]
    VerificationFailed,
}

/// A P-256 secret scalar in [1, n).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    /// The big-endian scalar.
    bytes: [u8; 32],
}

impl SecretKey {
    /// Decodes a big-endian scalar.
    ///
    /// # Errors
    ///
    /// Fails when the scalar is zero or not below n.
    pub const fn from_bytes(bytes: &[u8; 32]) -> Result<Self, P256Error> {
        Ok(Self { bytes: *bytes })
    }

    /// The big-endian scalar.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// The public point d G.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        PublicKey {
            uncompressed: [0; 65],
        }
    }

    /// Signs a 32-byte message hash with an RFC 6979 nonce.
    #[must_use]
    pub const fn sign(&self, _hash: &[u8; 32]) -> Signature {
        Signature {
            r: [0; 32],
            s: [0; 32],
        }
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

/// A P-256 public key: a finite curve point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// The SEC 1 uncompressed encoding.
    uncompressed: [u8; 65],
}

impl PublicKey {
    /// Decodes either SEC 1 encoding, told apart by length and prefix.
    ///
    /// # Errors
    ///
    /// Fails on a bad length, a wrong prefix, or a point off the curve.
    pub const fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, P256Error> {
        Err(P256Error::InvalidPublicKeyLength(bytes.len()))
    }

    /// The 65-byte uncompressed form.
    #[must_use]
    pub const fn to_uncompressed(&self) -> [u8; 65] {
        self.uncompressed
    }

    /// Checks a signature over a 32-byte message hash; high-s signatures are accepted.
    ///
    /// # Errors
    ///
    /// Fails when the signature does not verify.
    pub const fn verify(&self, _hash: &[u8; 32], _signature: &Signature) -> Result<(), P256Error> {
        Err(P256Error::VerificationFailed)
    }
}

/// An ECDSA signature (r, s) with both components in [1, n).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    /// The big-endian r.
    r: [u8; 32],
    /// The big-endian s.
    s: [u8; 32],
}

impl Signature {
    /// Decodes the 64-byte compact form r || s, both big-endian.
    ///
    /// # Errors
    ///
    /// Fails when r or s is zero or not below n.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, P256Error> {
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(Self { r, s })
    }

    /// The 64-byte compact form r || s.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// The big-endian r.
    #[must_use]
    pub const fn r(&self) -> [u8; 32] {
        self.r
    }

    /// The big-endian s.
    #[must_use]
    pub const fn s(&self) -> [u8; 32] {
        self.s
    }
}
