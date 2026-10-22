//! CRC-32C with the SSE4.2 `crc32` instruction.
//!
//! # Overview
//!
//! The instruction computes exactly the reflected Castagnoli step of the portable path.
//! It neither inverts its input nor its output, so it takes the same raw state.
//!
//! The instruction runs in constant time, though checksummed bytes are public anyway.

use std::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};

/// Advances a raw CRC state over the bytes, 8 bytes per instruction.
///
/// # Performance
///
/// One `crc32` on 64 bits has a 3-cycle latency and issues once per cycle.
/// A single dependency chain therefore runs near 8 bytes per 3 cycles.
#[target_feature(enable = "sse4.2")]
pub(super) fn update(crc: u32, bytes: &[u8]) -> u32 {
    let (blocks, tail) = bytes.as_chunks::<8>();
    let mut wide = u64::from(crc);
    for block in blocks {
        wide = _mm_crc32_u64(wide, u64::from_le_bytes(*block));
    }

    // Invariant: the 64-bit form leaves the upper 32 bits zero, so truncation is exact.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the instruction zeroes the upper half"
    )]
    let mut crc = wide as u32;
    for &byte in tail {
        crc = _mm_crc32_u8(crc, byte);
    }
    crc
}
