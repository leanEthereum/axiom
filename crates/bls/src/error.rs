//! Reasons a BLS key, signature, or aggregation is rejected.

use axiom_bls12_381::PointDecodeError;
use thiserror::Error;

/// A rejected key, signature, or aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BlsError {
    /// A secret key is zero or not below the group order r.
    #[error("secret key is zero or not below the group order")]
    InvalidSecretKey,

    /// A public key is not the encoding of a curve point in G1.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PointDecodeError),

    /// A public key is the point at infinity, which KeyValidate rejects.
    ///
    /// Its signatures would verify for every message.
    #[error("public key is the point at infinity")]
    InfinityPublicKey,

    /// A signature is not the encoding of a curve point in G2.
    #[error("invalid signature: {0}")]
    InvalidSignature(#[source] PointDecodeError),

    /// An aggregation received no inputs.
    #[error("cannot aggregate an empty list")]
    EmptyAggregate,

    /// A key aggregation produced the point at infinity, which is not a valid public key.
    #[error("aggregate public key is the point at infinity")]
    InfinityAggregate,
}
