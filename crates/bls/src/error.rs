//! Reasons a BLS key, signature, or aggregation is rejected.

use std::{error::Error, fmt};

use axiom_bls12_381::PointDecodeError;

/// A rejected key, signature, or aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlsError {
    /// A secret key is zero or not below the group order r.
    InvalidSecretKey,

    /// A public key is not the encoding of a curve point in G1.
    InvalidPublicKey(PointDecodeError),

    /// A public key is the point at infinity, which KeyValidate rejects.
    ///
    /// Its signatures would verify for every message.
    InfinityPublicKey,

    /// A signature is not the encoding of a curve point in G2.
    InvalidSignature(PointDecodeError),

    /// An aggregation received no inputs.
    EmptyAggregate,

    /// A key aggregation produced the point at infinity, which is not a valid public key.
    InfinityAggregate,
}

impl fmt::Display for BlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Each message names the rejected input and the reason.
        match self {
            Self::InvalidSecretKey => {
                f.write_str("secret key is zero or not below the group order")
            }
            Self::InvalidPublicKey(error) => write!(f, "invalid public key: {error}"),
            Self::InfinityPublicKey => f.write_str("public key is the point at infinity"),
            Self::InvalidSignature(error) => write!(f, "invalid signature: {error}"),
            Self::EmptyAggregate => f.write_str("cannot aggregate an empty list"),
            Self::InfinityAggregate => f.write_str("aggregate public key is the point at infinity"),
        }
    }
}

impl Error for BlsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Decoding failures carry the curve-level reason.
        match self {
            Self::InvalidPublicKey(error) | Self::InvalidSignature(error) => Some(error),
            _ => None,
        }
    }
}
