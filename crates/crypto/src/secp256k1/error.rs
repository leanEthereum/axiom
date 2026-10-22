//! Reasons a secp256k1 input or operation is refused.

use thiserror::Error;

/// A malformed key or signature, or a signature that does not check out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Secp256k1Error {
    /// A secret key is zero or not below the group order.
    #[error("secret key is zero or not below the group order")]
    InvalidSecretKey,

    /// A public key encoding has the wrong length or prefix, or is off the curve.
    #[error("invalid public key encoding")]
    InvalidPublicKey,

    /// A signature component is zero or not below the group order.
    #[error("signature component is zero or not below the group order")]
    InvalidSignature,

    /// A recovery identifier is above 3.
    #[error("recovery id {0} is above 3")]
    InvalidRecoveryId(u8),

    /// A signature has its s in the upper half of the order.
    ///
    /// Such signatures are malleable copies of low-s ones, so strict verification refuses them.
    #[error("signature s is in the upper half of the order")]
    HighS,

    /// A signature does not verify under the key.
    #[error("signature verification failed")]
    VerificationFailed,

    /// No public key can be recovered from the signature and hash.
    #[error("public key recovery failed")]
    RecoveryFailed,
}
