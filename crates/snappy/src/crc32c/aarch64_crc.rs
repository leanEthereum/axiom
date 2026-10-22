//! CRC-32C with the ARMv8 CRC32C instructions.
//!
//! # Overview
//!
//! CRC32CX and CRC32CB compute the reflected Castagnoli step of the portable path.
//! They neither invert their input nor their output, so they take the same raw state.
//!
//! The instructions run in constant time, though checksummed bytes are public anyway.

use std::arch::aarch64::{__crc32cb, __crc32cd};

/// Advances a raw CRC state over the bytes, 8 bytes per instruction.
///
/// # Performance
///
/// One dependency chain of 64-bit steps covers the input.
/// Its latency, not the issue rate, bounds the throughput.
#[target_feature(enable = "crc")]
pub(super) fn update(mut crc: u32, bytes: &[u8]) -> u32 {
    let (blocks, tail) = bytes.as_chunks::<8>();
    for block in blocks {
        crc = __crc32cd(crc, u64::from_le_bytes(*block));
    }
    for &byte in tail {
        crc = __crc32cb(crc, byte);
    }
    crc
}
