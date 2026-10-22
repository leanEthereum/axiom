//! Synchronized hash-based signatures: generalized XMSS over Poseidon1 and the KoalaBear field.
//!
//! # Overview
//!
//! A key pair signs at most once per epoch, over a lifetime of 2^h epochs.
//! Each epoch has a one-time key: v hash chains of length w, whose ends hash into a Merkle leaf.
//! The public key is the Merkle root over the epochs the key is active in.
//!
//! To sign a message at an epoch, the signer:
//!
//! 1. encodes the message into a codeword x with sum T, retrying fresh randomness until it hits;
//! 2. reveals chain i at position x_i;
//! 3. attaches the epoch's authentication path.
//!
//! A verifier walks each chain to its end, rebuilds the leaf, and climbs to the root.
//! The fixed sum makes codewords incomparable, so no signature walks forward into another.
//!
//! # Security
//!
//! Every recommended instantiation targets 128 bits of classical and 64 bits of quantum security.
//! The proof is in the standard model, from explicit properties of the tweakable hash.
//! It holds only if no key signs twice in one epoch: the caller keeps that ledger.
//!
//! Key generation, the PRF and the chain walks of signing handle secrets.
//! They run in constant time: field reductions select with masks, and SHAKE has no secret branch.
//! Encoding retries and Merkle paths depend only on public data.
//!
//! # Interoperability
//!
//! Keys, signatures, and every intermediate hash match the reference instantiations bit for bit.
//! Decoding is stricter: a non-canonical field element or a wrong length is refused.
//!
//! References:
//!
//! - Drake, Khovratovich, Kudinov, Wagner, "Hash-Based Multi-Signatures for Post-Quantum Ethereum", eprint 2025/055.
//! - Drake, Khovratovich, Kudinov, Wagner, "LeanSig for Post-Quantum Ethereum", eprint 2025/1332.
//! - Khovratovich, Kudinov, Wagner, "At the Top of the Hypercube", eprint 2025/889.
//! - Herold, Khovratovich, Kudinov, Tessaro, Wagner, "Aborting Random Oracles", eprint 2026/016.
//! - Grassi, Khovratovich, Rechberger, Roy, Schofnegger, "Poseidon", USENIX Security 2021.

mod codec;
mod encoding;
mod entropy;
mod error;
mod field;
mod instantiation;
mod keys;
mod merkle;
mod one_time;
mod parallel;
mod poseidon;
mod prf;
mod scheme;
mod tweak_hash;
mod words;

pub use encoding::MESSAGE_LEN;
pub use entropy::{Entropy, SeedStream};
pub use error::{DecodeError, EncodingError, KeyGenError, PrepareError, SignError, VerifyError};
pub use field::KoalaBear;
pub use instantiation::{ChunkSize, HypercubeLifetime, Instantiation, Target, TargetSumLifetime};
pub use keys::{LeafEpoch, PublicKey, SecretKey, Signature};
pub use one_time::{BottomTree, Preparation};
pub use poseidon::{POSEIDON1_16, POSEIDON1_24, Poseidon1};
pub use scheme::Scheme;
pub use words::{Digest, PublicParameter, Randomness, Words};
