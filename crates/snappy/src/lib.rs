//! Snappy compression, as the consensus networking layer uses it.
//!
//! # Overview
//!
//! Two formats share one compressor.
//!
//! - The raw block format compresses one message whole.
//!   Gossip carries every message in it.
//! - The framing format splits a stream into checksummed chunks of at most 64 KiB.
//!   Req/resp carries every payload in it.
//!
//! Decoders take the largest output the caller accepts.
//! The consensus p2p spec bounds every message size, so hostile input cannot force a large allocation.
//!
//! CRC-32C, the framing format's checksum, uses SSE4.2 or the ARMv8 CRC extension when present.
//!
//! # Examples
//!
//! ```
//! use axiom_snappy::{frame, raw};
//!
//! let message = b"attestation attestation attestation".repeat(10);
//!
//! let block = raw::compress(&message);
//! assert_eq!(raw::decompress(&block, 1 << 20).unwrap(), message);
//!
//! let stream = frame::compress(&message);
//! assert_eq!(frame::decompress(&stream, 1 << 20).unwrap(), message);
//! ```

mod crc32c;
mod error;
pub mod frame;
pub mod raw;

pub use crc32c::Crc32c;
pub use error::SnappyError;
