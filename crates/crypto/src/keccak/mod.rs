//! The Keccak family: the permutation, Ethereum's Keccak-256, and the SHA-3 standard of FIPS 202.
//!
//! # Overview
//!
//! Every hash here is one sponge over Keccak-f\[1600\].
//! They differ in their rate and in the domain byte that starts the padding.
//!
//! - Keccak-256 hashes public keys into node identities and addresses.
//! - SHA3-224, SHA3-256, SHA3-384 and SHA3-512 are the fixed-length hashes of FIPS 202.
//! - SHAKE128 and SHAKE256 squeeze outputs of any length, as the hash-based signatures' PRF needs.
//!
//! The permutation has no data-dependent branch or index, so every hash runs in constant time.

mod keccak256;
mod permutation;
mod sha3;
mod shake;
mod sponge;

pub use keccak256::Keccak256;
pub use permutation::KeccakF1600;
pub use sha3::{Sha3, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use shake::{Shake, Shake128, Shake256, ShakeReader};
