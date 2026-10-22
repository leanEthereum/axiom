//! The light client sync protocol: following the chain through sync committee signatures.
//!
//! # Overview
//!
//! A light client keeps no state beyond two sync committees and a few headers.
//! It trusts a header once a supermajority of the current sync committee signs it.
//!
//! Each period's committee is proven in the previous period's state.
//! The client therefore walks forward one committee at a time from a trusted bootstrap.
//!
//! See the Altair `light-client/sync-protocol.md`, as amended by Capella, Deneb, and Electra.

mod branch;
mod error;
mod quality;
mod store;

pub use error::LightClientError;
pub use quality::UpdateQuality;
pub use store::LightClientStore;
