//! Merkleization: hashing values into binary trees, and proving leaves against roots.

mod gindex;
mod merkleizer;
mod progressive;
mod proof;
mod zero;

pub use gindex::GeneralizedIndex;
pub use merkleizer::Merkleizer;
pub use progressive::ProgressiveMerkleizer;
pub use proof::MerkleProof;
pub use zero::ZeroHashes;
