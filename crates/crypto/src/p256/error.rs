//! Reasons a P-256 input or operation is refused.

use thiserror::Error;

/// A malformed key or signature, or a signature that does not check out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum P256Error {
    /// A secret key is zero or not below the group order.
    #[error("secret key is zero or not below the group order")]
    InvalidSecretKey,

    /// A public key encoding has a wrong prefix, a coordinate not below p, or a point off the curve.
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
        /// Byte offset of the component in the compact form: 0 for r, 32 for s.
        offset: usize,
    },

    /// A signature does not verify under the key.
    #[error("signature verification failed")]
    VerificationFailed,
}
