//! Reasons a node record is refused.

use axiom_crypto::secp256k1::Secp256k1Error;
use axiom_rlp::RlpError;
use thiserror::Error;

use crate::base64::Base64Error;

/// A node record that breaks EIP-778 or the "v4" identity scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EnrError {
    /// The encoding exceeds 300 bytes.
    #[error("record of {len} bytes exceeds 300")]
    TooLarge {
        /// Bytes in the encoding.
        len: usize,
    },

    /// The bytes are not canonical RLP of the record shape.
    #[error("record encoding: {0}")]
    Rlp(#[from] RlpError),

    /// The text form lacks the `enr:` prefix.
    #[error("record text lacks the enr: prefix")]
    MissingPrefix,

    /// The text form is not unpadded URL-safe base64.
    #[error("record text: {0}")]
    Base64(#[from] Base64Error),

    /// The keys are not in strictly increasing order.
    ///
    /// Sorted keys make the encoding unique, and strictness rules out duplicates.
    #[error("record key {position} does not exceed the key before it")]
    UnsortedKeys {
        /// Position of the first key out of order, counting pairs from zero.
        position: usize,
    },

    /// The record names no identity scheme.
    #[error("record names no identity scheme")]
    MissingScheme,

    /// The record names an identity scheme other than "v4".
    ///
    /// The scheme name is free-form bytes, so the error does not carry it.
    #[error("record identity scheme is not v4")]
    UnsupportedScheme,

    /// The record carries no secp256k1 key.
    #[error("record has no secp256k1 key")]
    MissingPublicKey,

    /// The record's secp256k1 key is not a point on the curve.
    #[error("record secp256k1 key: {0}")]
    InvalidPublicKey(#[source] Secp256k1Error),

    /// The signature is malformed or does not verify under the record's key.
    #[error("record signature: {0}")]
    InvalidSignature(#[source] Secp256k1Error),

    /// The signature does not have the 64 bytes of the "v4" scheme.
    #[error("record signature has {len} bytes, not 64")]
    SignatureLength {
        /// Bytes in the signature.
        len: usize,
    },
}
