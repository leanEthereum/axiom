//! The one place CRC-32C chooses its implementation.
//!
//! # Overview
//!
//! Axiom ships one binary to many CPUs.
//! Compile-time gating alone would bind that binary to the build machine's features.
//! So the CPU is asked at run time, once per checksum, and the answer travels with it.
//!
//! The `axiom_portable` cfg pins the portable path, whatever the CPU reports.
//! CI passes it through the compiler flags to test the fallback on hardware that has the extensions.
//! Nothing else reads it.

#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;

#[cfg(target_arch = "aarch64")]
use super::aarch64_crc;
use super::portable;
#[cfg(target_arch = "x86_64")]
use super::x86_64_sse42;

/// A CRC-32C implementation the running CPU supports.
///
/// The variant stays private, so only detection can name a hardware path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct Backend(Kernel);

/// The implementations, one per target and feature set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kernel {
    /// Slicing-by-8 tables, on every target.
    Portable,
    /// The SSE4.2 instruction.
    #[cfg(target_arch = "x86_64")]
    Sse42,
    /// The ARMv8 CRC extension.
    #[cfg(target_arch = "aarch64")]
    ArmCrc,
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
        if is_x86_feature_detected!("sse4.2") {
            return Self(Kernel::Sse42);
        }
        #[cfg(target_arch = "aarch64")]
        if is_aarch64_feature_detected!("crc") {
            return Self(Kernel::ArmCrc);
        }
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

    /// Advances a raw CRC state over the bytes.
    pub(super) fn update(self, crc: u32, bytes: &[u8]) -> u32 {
        match self.0 {
            Kernel::Portable => portable::update(crc, bytes),
            // SAFETY: only detection builds this kernel, after the CPU reported SSE4.2.
            // That is the only feature the function enables.
            #[cfg(target_arch = "x86_64")]
            Kernel::Sse42 => unsafe { x86_64_sse42::update(crc, bytes) },
            // SAFETY: only detection builds this kernel, after the CPU reported the CRC extension.
            // That is the only feature the function enables.
            #[cfg(target_arch = "aarch64")]
            Kernel::ArmCrc => unsafe { aarch64_crc::update(crc, bytes) },
        }
    }
}
