//! Reasons a secp256k1 input or operation is refused.

use thiserror::Error;

/// A malformed key or signature, or a signature that does not check out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Secp256k1Error {
    /// A secret key is zero or not below the group order.
    #[error("secret key is zero or not below the group order")]
    InvalidSecretKey,

    /// A public key encoding has a wrong prefix, or its point is off the curve.
    #[error("invalid public key encoding")]
    InvalidPublicKey,

    /// A public key encoding is neither 33 nor 65 bytes long.
    ///
    /// The value is the length received.
    #[error("public key encoding of {0} bytes is neither 33 nor 65")]
    InvalidPublicKeyLength(usize),

    /// A signature component is zero or not below the group order.
    #[error("signature component at byte {offset} is zero or not below the group order")]
    InvalidSignature {
        /// Byte offset of the component in the signature: 0 for r, 32 for s.
        offset: usize,
    },

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
