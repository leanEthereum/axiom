//! Reasons an RSA key, signature, or operation is refused.

use thiserror::Error;

/// A malformed key, a signature that does not check out, or a signing fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RsaError {
    /// The modulus is even, so it is no product of two odd primes.
    #[error("modulus is even")]
    EvenModulus,

    /// The modulus size is outside the supported range.
    #[error("modulus of {bits} bits is outside {min} to {max}")]
    ModulusSize {
        /// The bit length received.
        bits: usize,
        /// The smallest bit length accepted.
        min: usize,
        /// The largest bit length accepted.
        max: usize,
    },

    /// The public exponent is even, so it has no inverse modulo the even group order.
    #[error("public exponent is even")]
    EvenExponent,

    /// The public exponent is below 3.
    #[error("public exponent {exponent} is below 3")]
    ExponentTooSmall {
        /// The exponent received.
        exponent: u64,
    },

    /// The public exponent is not below the modulus.
    #[error("public exponent of {exponent_bits} bits is not below the {modulus_bits}-bit modulus")]
    ExponentTooLarge {
        /// The bit length of the exponent.
        exponent_bits: usize,
        /// The bit length of the modulus.
        modulus_bits: usize,
    },

    /// A digest length differs from the output length of its hash.
    #[error("digest of {actual} bytes, expected {expected}")]
    DigestLength {
        /// The hash output length.
        expected: usize,
        /// The length received.
        actual: usize,
    },

    /// A signature length differs from the modulus length.
    #[error("signature of {actual} bytes, expected {expected}")]
    SignatureLength {
        /// The modulus length in bytes.
        expected: usize,
        /// The length received.
        actual: usize,
    },

    /// A signature, read as an integer, is not below the modulus.
    #[error("signature is not below the modulus")]
    SignatureOutOfRange,

    /// The modulus is too short for the encoded message.
    #[error("encoded message needs {required} bytes but the modulus offers {available}")]
    EncodingTooShort {
        /// The bytes the encoding needs.
        required: usize,
        /// The bytes the modulus offers.
        available: usize,
    },

    /// A signature does not verify under the key.
    #[error("signature verification failed")]
    VerificationFailed,

    /// A prime factor is even or below 3.
    #[error("prime factor {index} is even or below 3")]
    InvalidPrime {
        /// Which factor: 0 for p, 1 for q.
        index: usize,
    },

    /// The modulus differs from the product of the two primes.
    #[error("modulus is not the product of the two primes")]
    PrimeProductMismatch,

    /// A CRT exponent is not the private exponent reduced modulo its prime minus one.
    ///
    /// It also fires when the public exponent times the CRT exponent is not 1 modulo that prime minus one.
    #[error("CRT exponent {index} does not match the private and public exponents")]
    CrtExponentMismatch {
        /// Which exponent: 0 for the one modulo p - 1, 1 for the one modulo q - 1.
        index: usize,
    },

    /// The CRT coefficient is not the inverse of q modulo p.
    #[error("CRT coefficient is not the inverse of q modulo p")]
    CoefficientMismatch,

    /// A fresh signature failed its check against the public key.
    ///
    /// A fault during the private computation would leak a prime, so the signature is withheld.
    #[error("signature failed the check against the public key, so it was withheld")]
    FaultDetected,
}
