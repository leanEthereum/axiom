//! AES-128 with its CTR and GCM modes, the ciphers of discv5 packets.
//!
//! # Overview
//!
//! discv5 uses two modes of one block cipher.
//!
//! - AES-128-CTR masks each packet header under the destination node's identifier.
//! - AES-128-GCM seals each message under a session key.
//!
//! # Performance
//!
//! The block cipher and GHASH each choose an implementation once, at run time.
//!
//! - On x86_64, AES-NI encrypts and PCLMULQDQ multiplies in GHASH.
//! - On aarch64, the ARMv8 AES instructions encrypt and PMULL multiplies in GHASH.
//! - Elsewhere a bitsliced, table-free AES and a constant-time carry-less multiply take over.
//!
//! Property tests pin each hardware path to its portable reference.

mod cipher;
mod ctr;
mod gcm;
mod ghash;

pub use cipher::Aes128;
pub use ctr::Aes128Ctr;
pub use gcm::Aes128Gcm;

/// Bytes in one AES block.
const BLOCK_LEN: usize = 16;
