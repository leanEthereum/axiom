//! The one place GHASH chooses its implementation.
//!
//! # Overview
//!
//! Axiom ships one binary to many CPUs.
//! Compile-time gating alone would bind that binary to the build machine's features.
//! So the CPU is asked at run time, once per hash, and the answer travels with it.
//!
//! The `axiom_portable` cfg pins the portable path, whatever the CPU reports.
//! CI passes it through the compiler flags to test the fallback on hardware that has the extensions.
//! Nothing else reads it.

#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;

#[cfg(target_arch = "aarch64")]
use super::aarch64_pmull::PmullGhash;
use super::gf128::Gf128;
#[cfg(target_arch = "x86_64")]
use super::x86_64_pclmul::ClmulGhash;
use crate::aes::BLOCK_LEN;

/// A GHASH implementation the running CPU supports.
///
/// The variant stays private, so only detection can name a hardware path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Backend(Kernel);

/// The implementations, one per target and feature set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kernel {
    /// The masked-integer carry-less product, on every target.
    Portable,
    /// PCLMULQDQ, with SSSE3 for the byte shuffles.
    #[cfg(target_arch = "x86_64")]
    Pclmul,
    /// PMULL from the ARMv8 cryptography extension.
    #[cfg(target_arch = "aarch64")]
    Pmull,
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
        if is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3") {
            return Self(Kernel::Pclmul);
        }
        #[cfg(target_arch = "aarch64")]
        if is_aarch64_feature_detected!("aes") && is_aarch64_feature_detected!("pmull") {
            return Self(Kernel::Pmull);
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

    /// Absorbs whole blocks into the running value and returns the new value.
    ///
    /// The powers are H, H^2, H^3 and H^4.
    /// Every path holds values in the natural bit order, so they share state.
    pub(super) fn absorb(
        self,
        powers: &[Gf128; 4],
        acc: Gf128,
        blocks: &[[u8; BLOCK_LEN]],
    ) -> Gf128 {
        match self.0 {
            // Horner's rule, one block at a time.
            Kernel::Portable => blocks.iter().fold(acc, |acc, block| {
                (acc ^ Gf128::from_block(block)) * powers[0]
            }),
            // SAFETY: only detection builds this kernel, after the CPU reported PCLMULQDQ and SSSE3.
            // Those are the features the function enables, with SSE2 from the x86_64 baseline.
            #[cfg(target_arch = "x86_64")]
            Kernel::Pclmul => Gf128::from_bits(unsafe {
                ClmulGhash::update(&powers.map(Gf128::to_bits), acc.to_bits(), blocks)
            }),
            // SAFETY: only detection builds this kernel, after the CPU reported AES and PMULL.
            // Those are the features the function enables, with NEON from the aarch64 baseline.
            #[cfg(target_arch = "aarch64")]
            Kernel::Pmull => Gf128::from_bits(unsafe {
                PmullGhash::update(&powers.map(Gf128::to_bits), acc.to_bits(), blocks)
            }),
        }
    }
}
