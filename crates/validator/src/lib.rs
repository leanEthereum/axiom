//! The validator client: it holds keys, signs, and performs duties through beacon nodes.
//!
//! # Overview
//!
//! The client is a set of services around one signing seam.
//!
//! - Keys come from EIP-2335 keystores, derived by EIP-2333 from a BIP-39 mnemonic.
//! - Every signature passes the EIP-3076 slashing protection database first.
//! - Duties reach the chain through the standard beacon API, with fallback across nodes.
//! - The keymanager API lets an operator add and remove keys while the client runs.
//!
//! Signing separates three things.
//!
//! 1. What is signed: a message, its domain, and its signing root.
//! 2. Whether signing it is safe: the slashing protection checks.
//! 3. How it is signed: the scheme, BLS today, a hash-based scheme tomorrow.

pub mod beacon;
pub mod duties;
pub mod keymanager;
pub mod keys;
pub mod protection;
pub mod signing;
pub mod validators;
