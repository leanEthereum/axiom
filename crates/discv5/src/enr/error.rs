//! Reasons a node record is refused.

use std::{error::Error, fmt};

use axiom_crypto::secp256k1::Secp256k1Error;
use axiom_rlp::RlpError;

use crate::base64::Base64Error;

/// A node record that breaks EIP-778 or the "v4" identity scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnrError {
    /// The encoding exceeds 300 bytes.
    TooLarge {
        /// Bytes in the encoding.
        len: usize,
    },

    /// The bytes are not canonical RLP of the record shape.
    Rlp(RlpError),

    /// The text form lacks the `enr:` prefix.
    MissingPrefix,

    /// The text form is not unpadded URL-safe base64.
    Base64(Base64Error),

    /// The keys are not in strictly increasing order.
    ///
    /// Sorted keys make the encoding unique, and strictness rules out duplicates.
    UnsortedKeys,

    /// The record names no identity scheme.
    MissingScheme,

    /// The record names an identity scheme other than "v4".
    UnsupportedScheme,

    /// The record carries no valid compressed secp256k1 key.
    InvalidPublicKey,

    /// The signature is malformed or does not verify under the record's key.
    InvalidSignature(Secp256k1Error),

    /// The signature does not have the 64 bytes of the "v4" scheme.
    SignatureLength {
        /// Bytes in the signature.
        len: usize,
    },
}

impl fmt::Display for EnrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len } => write!(f, "record of {len} bytes exceeds 300"),
            Self::Rlp(error) => write!(f, "record encoding: {error}"),
            Self::MissingPrefix => f.write_str("record text lacks the enr: prefix"),
            Self::Base64(error) => write!(f, "record text: {error}"),
            Self::UnsortedKeys => f.write_str("record keys are not strictly increasing"),
            Self::MissingScheme => f.write_str("record names no identity scheme"),
            Self::UnsupportedScheme => f.write_str("record identity scheme is not v4"),
            Self::InvalidPublicKey => f.write_str("record has no valid secp256k1 key"),
            Self::InvalidSignature(error) => write!(f, "record signature: {error}"),
            Self::SignatureLength { len } => {
                write!(f, "record signature has {len} bytes, not 64")
            }
        }
    }
}

impl Error for EnrError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rlp(error) => Some(error),
            Self::Base64(error) => Some(error),
            Self::InvalidSignature(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RlpError> for EnrError {
    fn from(error: RlpError) -> Self {
        Self::Rlp(error)
    }
}

impl From<Base64Error> for EnrError {
    fn from(error: Base64Error) -> Self {
        Self::Base64(error)
    }
}
