//! Reasons a certificate, key, or signature is refused before any path is built.

use thiserror::Error;

use crate::der::DerError;

/// A certificate field, key, or signature that cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum X509Error {
    /// A structure is not strict DER of the expected shape.
    #[error("malformed DER: {0}")]
    Der(#[from] DerError),

    /// The version field names a version this profile does not accept.
    #[error("certificate version field {0} is not 2, meaning v3")]
    UnsupportedVersion(u64),

    /// A serial number is longer than RFC 5280, section 4.1.2.2, allows.
    #[error("serial number of {length} bytes exceeds {max}")]
    SerialTooLong {
        /// Content bytes of the serial number.
        length: usize,
        /// Most bytes allowed.
        max: usize,
    },

    /// The outer and inner signature algorithms differ, which RFC 5280, section 4.1.1.2, forbids.
    #[error("outer and inner signature algorithms differ")]
    AlgorithmMismatch,

    /// A signature algorithm is not one this stack verifies.
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,

    /// A public key algorithm or curve is not one this stack verifies.
    #[error("unsupported public key algorithm")]
    UnsupportedKeyAlgorithm,

    /// A public key does not decode to a valid key of its algorithm.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// An RSA modulus is smaller than this stack accepts.
    #[error("RSA modulus of {bits} bits is below the minimum of {min}")]
    RsaKeyTooSmall {
        /// Bits of the modulus.
        bits: usize,
        /// Fewest bits accepted.
        min: usize,
    },

    /// A signature algorithm cannot be made by the key it is checked against.
    #[error("signature algorithm does not match the key")]
    IncompatibleKey,

    /// A signature value is malformed for its algorithm.
    #[error("malformed signature value")]
    MalformedSignature,

    /// A signature does not verify under the key.
    #[error("signature does not verify")]
    InvalidSignature,

    /// The same extension appears twice, which RFC 5280, section 4.2, forbids.
    #[error("duplicate extension")]
    DuplicateExtension,

    /// A critical flag is written as an explicit false, which DER forbids for a default.
    #[error("explicit default critical flag")]
    ExplicitDefault,

    /// The extensions field is present but empty, which RFC 5280, section 4.1, forbids.
    #[error("empty extensions field")]
    EmptyExtensions,

    /// A known extension does not hold the value its definition requires.
    #[error("malformed extension")]
    InvalidExtension,

    /// A name constraint uses a form this stack does not evaluate.
    #[error("unsupported name constraint")]
    UnsupportedNameConstraint,
}
