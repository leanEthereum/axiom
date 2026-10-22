//! BLS signatures for Ethereum consensus.
//!
//! # Overview
//!
//! The ciphersuite is BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ of draft-irtf-cfrg-bls-signature-05.
//! It is the minimal-pubkey-size variant with proof of possession:
//!
//! - Public keys live in G1, at 48 bytes.
//! - Signatures live in G2, at 96 bytes.
//! - Messages hash to G2 with RFC 9380 under the ciphersuite name as tag.
//! - Proofs of possession, checked at deposit time, make key aggregation safe.
//!
//! The consensus specs use it in `specs/phase0/beacon-chain.md` and `specs/altair/bls.md`.

mod error;
mod public_key;
mod secret_key;
mod signature;
mod signature_set;

pub use error::BlsError;
pub use public_key::PublicKey;
pub use secret_key::SecretKey;
pub use signature::Signature;
pub use signature_set::SignatureSet;

/// Domain separation tag of the proof-of-possession ciphersuite, used to hash messages.
///
/// Fixed by draft-irtf-cfrg-bls-signature-05 section 4.2.3 and by the consensus specs.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
