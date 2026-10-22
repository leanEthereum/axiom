//! The one place the AES block cipher chooses its implementation.
//!
//! # Overview
//!
//! Axiom ships one binary to many CPUs.
//! Compile-time gating alone would bind that binary to the build machine's features.
//! So the CPU is asked at run time, once per cipher, and the answer travels with it.
//!
//! The `axiom_portable` cfg pins the portable path, whatever the CPU reports.
//! CI passes it through the compiler flags to test the fallback on hardware that has the extensions.
//! Nothing else reads it.

#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;

#[cfg(target_arch = "aarch64")]
use super::aarch64_aes::ArmSchedule;
use super::portable::RoundKeys;
#[cfg(target_arch = "x86_64")]
use super::x86_64_aesni::NiSchedule;

/// An AES implementation the running CPU supports.
///
/// The variant stays private, so only detection can name a hardware path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Backend(Kernel);

/// The implementations, one per target and feature set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kernel {
    /// The bitsliced circuit, on every target.
    Portable,
    /// AES-NI.
    #[cfg(target_arch = "x86_64")]
    AesNi,
    /// The ARMv8 cryptography extension.
    #[cfg(target_arch = "aarch64")]
    ArmAes,
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
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            return Self(Kernel::AesNi);
        }
        #[cfg(target_arch = "aarch64")]
        if is_aarch64_feature_detected!("aes") {
            return Self(Kernel::ArmAes);
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

    /// Expands a key into its eleven round keys.
    ///
    /// AES-NI loads the round keys of the portable schedule.
    #[cfg_attr(
        not(target_arch = "aarch64"),
        expect(
            clippy::unused_self,
            reason = "only the aarch64 path has its own key schedule"
        )
    )]
    pub(super) fn expand(self, key: &[u8; 16]) -> RoundKeys {
        #[cfg(target_arch = "aarch64")]
        if self.0 == Kernel::ArmAes {
            // SAFETY: only detection builds this kernel, after the CPU reported the AES extension.
            // That is the only feature the function enables.
            return RoundKeys::from_blocks(unsafe { ArmSchedule::expand(key) });
        }
        RoundKeys::expand(key)
    }

    /// Encrypts every block in place under the round keys.
    pub(super) fn encrypt_blocks(self, keys: &RoundKeys, blocks: &mut [[u8; 16]]) {
        match self.0 {
            Kernel::Portable => {
                for block in blocks {
                    keys.encrypt_block(block);
                }
            }
            // SAFETY: only detection builds this kernel, after the CPU reported AES-NI and SSE2.
            // Those are the features the function enables.
            #[cfg(target_arch = "x86_64")]
            Kernel::AesNi => unsafe { NiSchedule::encrypt(keys.as_blocks(), blocks) },
            // SAFETY: only detection builds this kernel, after the CPU reported the AES extension.
            // That is the only feature the function enables.
            #[cfg(target_arch = "aarch64")]
            Kernel::ArmAes => unsafe { ArmSchedule::encrypt(keys.as_blocks(), blocks) },
        }
    }
}
