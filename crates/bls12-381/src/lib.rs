//! The BLS12-381 pairing-friendly elliptic curve.
//!
//! # Overview
//!
//! BLS12-381 is a Barreto-Lynn-Scott curve of embedding degree 12 over a 381-bit prime field.
//! Ethereum uses it for BLS signatures and for KZG commitments.
//!
//! ```text
//!     F_p                 base field, 381 bits
//!     F_p2 -> F_p6 -> F_p12   extension tower, the pairing's target field
//!     F_r                 scalar field, 255 bits, 2-adicity 32
//!
//!     G1 = E(F_p)[r]       E : y^2 = x^3 + 4             48-byte points
//!     G2 = E'(F_p2)[r]     E': y^2 = x^3 + 4(1 + u)      96-byte points
//!     e : G1 x G2 -> GT    optimal ate pairing, GT inside F_p12
//! ```
//!
//! The crate follows these references:
//!
//! - Encodings: the ZCash BLS12-381 serialization format.
//! - Hashing to G2: RFC 9380, suite BLS12381G2_XMD:SHA-256_SSWU_RO_.
//! - Subgroup checks: Scott, eprint 2021/1130.
//! - Addition formulas: Renes, Costello, and Batina, eprint 2015/1060.
//!
//! Operations on secret scalars run in constant time.
//! Operations named vartime, and hashing, decoding, and multi-scalar multiplication, take public inputs only.
//!
//! # Examples
//!
//! ```
//! use axiom_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
//!
//! let a = Scalar::from_u64(6);
//! let b = Scalar::from_u64(7);
//! let p = G1Affine::from(G1Projective::GENERATOR * a);
//! let q = G2Affine::from(G2Projective::GENERATOR * b);
//!
//! // Bilinearity: e(6 G1, 7 G2) = e(42 G1, G2).
//! let p42 = G1Affine::from(G1Projective::GENERATOR * (a * b));
//! assert_eq!(Gt::pairing(&p, &q), Gt::pairing(&p42, &G2Affine::GENERATOR));
//!
//! // Points round-trip through the 48-byte compressed encoding.
//! assert_eq!(G1Affine::from_compressed(&p.to_compressed()), Ok(p));
//! ```

mod arithmetic;
mod encoding;
mod error;
mod fp;
mod fp12;
mod fp2;
mod fp6;
mod g1;
mod g2;
mod hash_to_curve;
mod msm;
mod pairing;
mod scalar;

pub use error::PointDecodeError;
pub use fp::{FP_BYTES, Fp};
pub use fp2::Fp2;
pub use fp6::Fp6;
pub use fp12::Fp12;
pub use g1::{G1_COMPRESSED_BYTES, G1_UNCOMPRESSED_BYTES, G1Affine, G1Projective};
pub use g2::{G2_COMPRESSED_BYTES, G2_UNCOMPRESSED_BYTES, G2Affine, G2Projective};
pub use pairing::Gt;
pub use scalar::{SCALAR_BYTES, Scalar};

/// The absolute value of the curve parameter x = -0xd201000000010000.
///
/// Everything about the curve derives from x: p = (x - 1)^2 (x^4 - x^2 + 1) / 3 + x and r = x^4 - x^2 + 1.
/// It has only six set bits, which keeps the Miller loop and the subgroup checks short.
pub(crate) const BLS_X: u64 = 0xd201_0000_0001_0000;
