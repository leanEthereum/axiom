//! Reasons a secp256k1 input or operation is refused.

use std::{error::Error, fmt};

/// A malformed key or signature, or a signature that does not check out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Secp256k1Error {
    /// A secret key is zero or not below the group order.
    InvalidSecretKey,

    /// A public key encoding has the wrong length or prefix, or is off the curve.
    InvalidPublicKey,

    /// A signature component is zero or not below the group order.
    InvalidSignature,

    /// A recovery identifier is above 3.
    InvalidRecoveryId(u8),

    /// A signature has its s in the upper half of the order.
    ///
    /// Such signatures are malleable copies of low-s ones, so strict verification refuses them.
    HighS,

    /// A signature does not verify under the key.
    VerificationFailed,

    /// No public key can be recovered from the signature and hash.
    RecoveryFailed,
}

impl fmt::Display for Secp256k1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => {
                f.write_str("secret key is zero or not below the group order")
            }
            Self::InvalidPublicKey => f.write_str("invalid public key encoding"),
            Self::InvalidSignature => {
                f.write_str("signature component is zero or not below the group order")
            }
            Self::InvalidRecoveryId(id) => write!(f, "recovery id {id} is above 3"),
            Self::HighS => f.write_str("signature s is in the upper half of the order"),
            Self::VerificationFailed => f.write_str("signature verification failed"),
            Self::RecoveryFailed => f.write_str("public key recovery failed"),
        }
    }
}

impl Error for Secp256k1Error {}
