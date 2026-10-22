//! Simple Serialize, the encoding and merkleization of every consensus object.
//!
//! # Overview
//!
//! SSZ gives each type two views of a value.
//!
//! - The serialization is a compact byte string, sent over the wire and stored on disk.
//! - The hash tree root is a 32-byte commitment, signed by validators and proven against.
//!
//! The specification lives in `ethereum/ssz-specs`.
//! Merkle proofs follow the consensus specs' `ssz/merkle-proofs.md`.
//!
//! # Examples
//!
//! ```
//! use axiom_ssz::{Const, List, Ssz};
//!
//! let balances = List::<u64, Const<8>>::try_from(vec![32, 31]).unwrap();
//!
//! let bytes = balances.encode();
//! assert_eq!(bytes.len(), 16);
//! assert_eq!(List::<u64, Const<8>>::decode(&bytes).unwrap(), balances);
//! ```

mod basic;
mod collections;
mod container;
mod error;
mod length;
mod merkle;
mod offset;
mod root;
mod ssz;
mod uint256;

pub use collections::{BitList, BitVector, ByteList, ByteVector, CapacityError, List, Vector};
pub use container::{Container, FieldDecoder, FieldVisitor};
pub use error::DecodeError;
pub use length::{Const, Length};
pub use merkle::{GeneralizedIndex, MerkleProof, Merkleizer, ZeroHashes};
pub use root::Root;
pub use ssz::{BYTES_PER_CHUNK, BYTES_PER_LENGTH_OFFSET, Ssz};
pub use uint256::U256;
