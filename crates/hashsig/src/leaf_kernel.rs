//! The leaves of a bottom tree, sixteen epochs at a time in SIMD lanes, on the widest instruction set present.
//!
//! # Overview
//!
//! Key preparation spends nearly all its time walking chains: v * (w - 1) steps per epoch.
//! Sixteen epochs walk the same chain index in lockstep, one epoch per lane.
//! The lane-generic code is plain Rust; compiled under a wider target feature, the lanes become vector registers.
//!
//! The kernel is chosen once per process, and every kernel computes exactly the scalar leaves.
//!
//! # Performance
//!
//! The scalar permutation is bound by the 64-bit multiplier, one product per cycle.
//! A 512-bit register holds eight 64-bit products, so the lanes multiply the throughput.

use std::sync::OnceLock;

use crate::{one_time::OneTimeKeys, words::Digest};

/// Epochs per batch: sixteen 32-bit lanes fill a 512-bit register.
pub(crate) const LANES: usize = 16;

/// A kernel computing the leaves of one batch of epochs.
///
/// Kernels compiled for a target feature are unsafe to call where the feature is absent.
type Kernel = unsafe fn(&OneTimeKeys, &[u32; LANES]) -> [Digest; LANES];

/// The leaf kernel for this machine.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LeafKernel {
    /// The chosen kernel.
    run: Kernel,
}

impl LeafKernel {
    /// The widest kernel this machine runs, detected once per process.
    pub(crate) fn detect() -> Self {
        static KERNEL: OnceLock<LeafKernel> = OnceLock::new();
        *KERNEL.get_or_init(|| Self {
            run: Self::widest(),
        })
    }

    /// The portable kernel, the reference every other kernel equals.
    #[cfg(test)]
    pub(crate) const fn portable() -> Self {
        Self { run: portable }
    }

    /// The leaves of one batch of epochs.
    pub(crate) fn leaves(self, keys: &OneTimeKeys, epochs: &[u32; LANES]) -> [Digest; LANES] {
        // SAFETY: a kernel is chosen only after its target features are detected on this machine.
        unsafe { (self.run)(keys, epochs) }
    }

    /// The widest kernel among those compiled in that the CPU supports.
    #[cfg(all(target_arch = "x86_64", not(axiom_portable)))]
    fn widest() -> Kernel {
        if std::arch::is_x86_feature_detected!("avx512f") {
            avx512
        } else if std::arch::is_x86_feature_detected!("avx2") {
            avx2
        } else {
            portable
        }
    }

    /// The portable kernel, the only one on this target.
    #[cfg(not(all(target_arch = "x86_64", not(axiom_portable))))]
    fn widest() -> Kernel {
        portable
    }
}

/// Leaves in lanes as the baseline target compiles them.
fn portable(keys: &OneTimeKeys, epochs: &[u32; LANES]) -> [Digest; LANES] {
    keys.leaves_lanes(epochs)
}

/// Leaves in lanes with 256-bit vectors.
#[cfg(all(target_arch = "x86_64", not(axiom_portable)))]
#[target_feature(enable = "avx2")]
fn avx2(keys: &OneTimeKeys, epochs: &[u32; LANES]) -> [Digest; LANES] {
    keys.leaves_lanes(epochs)
}

/// Leaves in lanes with 512-bit vectors.
#[cfg(all(target_arch = "x86_64", not(axiom_portable)))]
#[target_feature(enable = "avx512f")]
fn avx512(keys: &OneTimeKeys, epochs: &[u32; LANES]) -> [Digest; LANES] {
    keys.leaves_lanes(epochs)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        entropy::SeedStream,
        instantiation::{ChunkSize, HypercubeLifetime, Instantiation, Target, TargetSumLifetime},
        prf::PrfKey,
        words::PublicParameter,
    };

    /// The one-time keys of an instantiation, from a stream.
    fn keys(instantiation: Instantiation) -> OneTimeKeys {
        let scheme = instantiation.scheme();
        let mut stream = SeedStream::new(b"kernel");
        let parameter = PublicParameter::sample(&mut stream);
        OneTimeKeys::new(
            scheme,
            PrfKey::sample(&mut stream),
            scheme.tweak_hash(parameter),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn every_kernel_computes_the_scalar_leaves(first in 0_u32..(1 << 18) - 16) {
            // The 2^32 hypercube with 8-element digests, and 2^18 with 7-element digests.
            let instantiations = [
                Instantiation::Hypercube(HypercubeLifetime::Epochs32),
                Instantiation::TargetSum {
                    lifetime: TargetSumLifetime::Epochs18,
                    chunk: ChunkSize::Four,
                    target: Target::Expected,
                },
            ];
            for instantiation in instantiations {
                let keys = keys(instantiation);
                let epochs: [u32; LANES] = std::array::from_fn(|lane| first + lane as u32);
                let expected = epochs.map(|epoch| keys.leaf(epoch));
                prop_assert_eq!(LeafKernel::detect().leaves(&keys, &epochs), expected);
                prop_assert_eq!(LeafKernel::portable().leaves(&keys, &epochs), expected);
            }
        }
    }
}
