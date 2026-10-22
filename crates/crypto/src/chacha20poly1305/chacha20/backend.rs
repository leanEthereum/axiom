//! The one place ChaCha20 chooses its implementation.
//!
//! # Overview
//!
//! Axiom ships one binary to many CPUs.
//! Compile-time gating alone would bind that binary to the build machine's features.
//! So the CPU is asked at run time, once per keystream, and the answer travels with it.
//!
//! The NEON kernel also requires a little-endian target, since it stores words in register order.
//!
//! The `axiom_portable` cfg pins the portable path, whatever the CPU reports.
//! CI passes it through the compiler flags to test the fallback on hardware that has the extensions.
//! Nothing else reads it.

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use std::arch::is_aarch64_feature_detected;
#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use super::aarch64_neon::{self, FourBlocks};
#[cfg(target_arch = "x86_64")]
use super::x86_64_avx2::{self, EightBlocks};
use super::{BLOCK_LEN, COUNTER};

/// A ChaCha20 implementation the running CPU supports.
///
/// The variant stays private, so only detection can name a vector path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Backend(Kernel);

/// The implementations, one per target and feature set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kernel {
    /// One block at a time with the scalar block function, on every target.
    Portable,
    /// Eight blocks per batch in AVX2 registers.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// Four blocks per batch in NEON registers.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    Neon,
}

impl Backend {
    /// The fastest path this CPU runs, or the portable one when the cfg forces it.
    pub(super) fn detect() -> Self {
        if cfg!(axiom_portable) {
            Self(Kernel::Portable)
        } else {
            Self::fastest()
        }
    }

    /// The fastest path this CPU runs.
    fn fastest() -> Self {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return Self(Kernel::Avx2);
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if is_aarch64_feature_detected!("neon") {
            return Self(Kernel::Neon);
        }
        Self(Kernel::Portable)
    }

    /// The portable reference.
    #[cfg(test)]
    pub(super) const fn portable() -> Self {
        Self(Kernel::Portable)
    }

    /// Every path this CPU runs, the portable reference first.
    ///
    /// Tests pin each one to the first, whether or not the portable path is forced.
    #[cfg(test)]
    pub(super) fn supported() -> Vec<Self> {
        let mut backends = vec![Self(Kernel::Portable)];
        let fastest = Self::fastest();
        if !backends.contains(&fastest) {
            backends.push(fastest);
        }
        backends
    }

    /// XORs as many whole batches as fit, advancing the block counter, and returns the rest.
    ///
    /// The caller has reserved every block of the data, so no batch wraps the counter.
    /// The portable path takes no batches and returns all the data.
    pub(super) fn xor_batches<'a>(self, state: &mut [u32; 16], data: &'a mut [u8]) -> &'a mut [u8] {
        match self.0 {
            Kernel::Portable => data,
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => {
                let (batches, rest) = data.as_chunks_mut::<{ x86_64_avx2::BLOCKS * BLOCK_LEN }>();
                for batch in batches {
                    // SAFETY: only detection builds this kernel, after the CPU reported AVX2.
                    // That is the only feature the function enables.
                    unsafe {
                        EightBlocks::xor_keystream(state, batch);
                    }
                    state[COUNTER] = state[COUNTER].wrapping_add(x86_64_avx2::BLOCKS as u32);
                }
                rest
            }
            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            Kernel::Neon => {
                let (batches, rest) = data.as_chunks_mut::<{ aarch64_neon::BLOCKS * BLOCK_LEN }>();
                for batch in batches {
                    // SAFETY: only detection builds this kernel, after the CPU reported NEON.
                    // That is the only feature the function enables.
                    unsafe {
                        FourBlocks::xor_keystream(state, batch);
                    }
                    state[COUNTER] = state[COUNTER].wrapping_add(aarch64_neon::BLOCKS as u32);
                }
                rest
            }
        }
    }
}
