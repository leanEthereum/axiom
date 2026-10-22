//! Domain scalars: every number and byte string with a protocol meaning gets its own type.

mod bls;
mod bytes;
mod epoch;
mod gwei;
mod hex;
mod indices;
mod kzg;
mod participation;
mod slot;

pub use bls::{BlsPubkey, BlsSignature};
pub use bytes::{
    Bytes32, Domain, DomainType, ExecutionAddress, ForkDigest, Hash32, Version, VersionedHash,
};
pub use epoch::Epoch;
pub use gwei::Gwei;
pub use hex::Hex;
pub use indices::{
    BlobIndex, ColumnIndex, CommitteeIndex, SubnetId, ValidatorIndex, WithdrawalIndex,
};
pub use kzg::{KzgCommitment, KzgProof};
pub use participation::ParticipationFlags;
pub use slot::Slot;
