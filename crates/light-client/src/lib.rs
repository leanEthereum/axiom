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
//! Five forks define their own data format, and each one upgrades the one before it.
//! The rules are written once over the fields, and each format supplies its header checks.
//!
//! See the Altair `light-client/sync-protocol.md`, as amended by Capella, Deneb, Electra, and Gloas.

mod altair;
mod branch;
mod capella;
pub mod combined;
mod data;
mod deneb;
mod electra;
mod error;
mod fork;
mod gloas;
mod layout;
mod quality;
mod store;

pub use altair::Altair;
pub use capella::Capella;
pub use data::{BootstrapData, UpdateData};
pub use deneb::Deneb;
pub use electra::Electra;
pub use error::LightClientError;
pub use fork::{Header, LightClientBlock, LightClientFork, Upgrade};
pub use gloas::Gloas;
pub use layout::{Execution, Layout};
pub use quality::UpdateQuality;
pub use store::LightClientStore;
