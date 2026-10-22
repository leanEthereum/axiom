//! One runner per kind of consensus spec vector.

mod blocks;
mod chain;
mod epoch_processing;
mod fork;
mod fork_choice;
mod gossip;
mod light_client;
mod merkle_proof;
mod networking;
mod operations;
mod rewards;
mod shuffling;
mod ssz_generic;
mod ssz_static;
mod transition;

pub use blocks::Blocks;
pub use chain::ChainReplay;
pub use epoch_processing::EpochProcessing;
pub use fork::Fork;
pub use fork_choice::StoreReplay;
pub use light_client::LightClient;
pub use merkle_proof::MerkleProofs;
pub use networking::Networking;
pub use operations::{Applied, OperationInput, Operations, Rejection};
pub use rewards::Rewards;
pub use shuffling::Shuffling;
pub use ssz_generic::SszGeneric;
pub use ssz_static::SszStatic;
pub use transition::Transition;
