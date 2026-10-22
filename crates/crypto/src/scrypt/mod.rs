//! scrypt, the memory-hard password-based key derivation of RFC 7914.
//!
//! # Overview
//!
//! EIP-2335 keystores encrypt validator keys under an scrypt-derived key.
//! The cost N sets how many blocks the derivation must keep in memory at once.
//! A guess at the password then costs memory as well as time, which custom hardware cannot shortcut.
//!
//! See Percival, "Stronger key derivation via sequential memory-hard functions", BSDCan 2009.

mod error;
mod params;
mod romix;
mod salsa;

pub use error::ScryptError;
pub use params::ScryptParams;
