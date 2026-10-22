//! CRC-32C with the ARMv8 `crc32c` instructions.

use std::arch::aarch64::{__crc32cb, __crc32cd};

/// Advances a raw CRC state over the bytes, 8 bytes per instruction.
///
/// Like the x86 instruction, it takes and returns the raw, uninverted state.
#[target_feature(enable = "crc")]
pub(crate) fn update(mut crc: u32, bytes: &[u8]) -> u32 {
    let (blocks, tail) = bytes.as_chunks::<8>();
    for block in blocks {
        crc = __crc32cd(crc, u64::from_le_bytes(*block));
    }
    for &byte in tail {
        crc = __crc32cb(crc, byte);
    }
    crc
}
