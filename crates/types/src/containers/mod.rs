//! The SSZ containers of the Fulu beacon chain.
//!
//! One file per protocol concept, each holding the containers the spec defines for it.

mod aggregate;
mod attestation;
mod blob;
mod block;
mod block_header;
mod checkpoint;
mod consolidation;
mod credential_change;
mod data_column;
mod deposit;
pub(crate) mod electra;
mod eth1;
mod execution;
mod exit;
mod fork;
mod historical;
mod light_client;
mod partial_column;
mod signing;
mod slashing;
mod state;
mod sync_committee;
mod validator;
mod withdrawal;

pub use aggregate::*;
pub use attestation::*;
pub use blob::*;
pub use block::*;
pub use block_header::*;
pub use checkpoint::*;
pub use consolidation::*;
pub use credential_change::*;
pub use data_column::*;
pub use deposit::*;
pub use eth1::*;
pub use execution::*;
pub use exit::*;
pub use fork::*;
pub use historical::*;
pub use light_client::*;
pub use partial_column::*;
pub use signing::*;
pub use slashing::*;
pub use state::*;
pub use sync_committee::*;
pub use validator::*;
pub use withdrawal::*;
