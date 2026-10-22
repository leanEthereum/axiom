//! The instantiations with recommended parameters, as one table per family.
//!
//! # Overview
//!
//! Every instantiation targets 128-bit classical and 64-bit quantum security.
//! Hash, parameter and randomness lengths follow the bounds of eprint 2025/055, section 6.
//!
//! Two encodings exist, both filtered by a target sum.
//!
//! - Base-p: the message hash, read as one integer, splits into base-w digits.
//!   Lifetimes 2^18 and 2^20, with chunk sizes of 1, 2, 4 or 8 bits.
//! - Aborting hypercube: each hash element splits into z base-w digits, or the hash aborts.
//!   Lifetime 2^32, 46 chains of length 8, and a lifetime 2^8 kept for tests only.
//!
//! A target sum at the expectation v * (w - 1) / 2 maximizes the code, so signing retries least.
//! A target 10% above it trades longer verification chains for a shorter signer walk.
//!
//! References:
//!
//! - Drake, Khovratovich, Kudinov, Wagner, "Hash-Based Multi-Signatures for Post-Quantum Ethereum", eprint 2025/055.
//! - Drake, Khovratovich, Kudinov, Wagner, "LeanSig for Post-Quantum Ethereum", eprint 2025/1332.
//! - Khovratovich, Kudinov, Wagner, "At the Top of the Hypercube", eprint 2025/889.
//! - Herold, Khovratovich, Kudinov, Tessaro, Wagner, "Aborting Random Oracles", eprint 2026/016.

use crate::{encoding::MessageHash, scheme::Scheme};

/// A hardcoded instantiation of the generalized XMSS scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Instantiation {
    /// The target-sum encoding over a base-p decoded message hash.
    TargetSum {
        /// The key lifetime.
        lifetime: TargetSumLifetime,
        /// Bits per codeword chunk.
        chunk: ChunkSize,
        /// Where the target sum sits.
        target: Target,
    },
    /// The target-sum encoding over the aborting hypercube message hash.
    Hypercube(HypercubeLifetime),
}

/// Lifetimes of the base-p instantiations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetSumLifetime {
    /// 2^18 epochs.
    Epochs18,
    /// 2^20 epochs.
    Epochs20,
}

/// Bits per codeword chunk w, so chains have 2^w positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChunkSize {
    /// One bit: 155 chains of length 2.
    One,
    /// Two bits: 78 chains of length 4.
    Two,
    /// Four bits: 39 chains of length 16.
    Four,
    /// Eight bits: 20 chains of length 256.
    ///
    /// The long chains make the codeword sum vary widely, so signing may exhaust its tries.
    Eight,
}

/// Where the target sum sits relative to the expected sum of a uniform codeword.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// At the expectation.
    Expected,
    /// At 1.1 times the expectation.
    TenPercentAbove,
}

/// Lifetimes of the aborting hypercube instantiations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HypercubeLifetime {
    /// 2^8 epochs and 4 chains: far below any security level, for fast tests only.
    TestOnly8,
    /// 2^32 epochs: 46 chains of length 8 and a target sum of 200.
    Epochs32,
}

impl Instantiation {
    /// Every instantiation, base-p lifetimes first.
    pub const ALL: [Self; 18] = {
        let lifetimes = [TargetSumLifetime::Epochs18, TargetSumLifetime::Epochs20];
        let chunks = [
            ChunkSize::One,
            ChunkSize::Two,
            ChunkSize::Four,
            ChunkSize::Eight,
        ];
        let targets = [Target::Expected, Target::TenPercentAbove];
        let mut all = [Self::Hypercube(HypercubeLifetime::TestOnly8); 18];
        let mut index = 0;
        while index < 16 {
            all[index] = Self::TargetSum {
                lifetime: lifetimes[index / 8],
                chunk: chunks[(index / 2) % 4],
                target: targets[index % 2],
            };
            index += 1;
        }
        all[17] = Self::Hypercube(HypercubeLifetime::Epochs32);
        all
    };

    /// The parameters of the instantiation.
    #[must_use]
    pub const fn scheme(self) -> Scheme {
        match self {
            Self::TargetSum {
                lifetime,
                chunk,
                target,
            } => {
                // Chains, chunk bits, and the target at the expectation and 10% above.
                let (dimension, bits, expected, above) = match chunk {
                    ChunkSize::One => (155, 1, 78, 86),
                    ChunkSize::Two => (78, 2, 117, 129),
                    ChunkSize::Four => (39, 4, 293, 322),
                    ChunkSize::Eight => (20, 8, 2550, 2805),
                };
                let log_lifetime = match lifetime {
                    TargetSumLifetime::Epochs18 => 18,
                    TargetSumLifetime::Epochs20 => 20,
                };
                // Chains of 256 positions at lifetime 2^20 need one more hash element.
                let hash_len = match (lifetime, chunk) {
                    (TargetSumLifetime::Epochs20, ChunkSize::Eight) => 8,
                    _ => 7,
                };
                Scheme {
                    log_lifetime,
                    dimension,
                    base: 1 << bits,
                    target_sum: match target {
                        Target::Expected => expected,
                        Target::TenPercentAbove => above,
                    },
                    hash_len,
                    rand_len: 6,
                    message_hash: MessageHash::BaseP { output_len: 5 },
                }
                .checked()
            }
            Self::Hypercube(lifetime) => {
                // p = 127 * 8^8 + 1, so each hash element yields 8 uniform base-8 digits.
                let (log_lifetime, dimension, target_sum) = match lifetime {
                    HypercubeLifetime::TestOnly8 => (8, 4, 6),
                    HypercubeLifetime::Epochs32 => (32, 46, 200),
                };
                Scheme {
                    log_lifetime,
                    dimension,
                    base: 8,
                    target_sum,
                    hash_len: 8,
                    rand_len: 7,
                    message_hash: MessageHash::Aborting {
                        output_len: 8,
                        digits_per_element: 8,
                        quotient: 127,
                    },
                }
                .checked()
            }
        }
    }
}

/// Every instantiation passes its parameter checks at compile time.
const _: () = {
    let mut index = 0;
    while index < Instantiation::ALL.len() {
        let _ = Instantiation::ALL[index].scheme();
        index += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_every_instantiation_once() {
        // 2 lifetimes * 4 chunk sizes * 2 targets, plus 2 hypercube lifetimes.
        for (i, a) in Instantiation::ALL.iter().enumerate() {
            for b in &Instantiation::ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(
            Instantiation::ALL.contains(&Instantiation::Hypercube(HypercubeLifetime::Epochs32))
        );
    }

    #[test]
    fn targets_sit_at_and_above_the_expected_sum() {
        // The expected sum v * (w - 1) / 2 and 1.1 times it, both rounded up.
        //
        //     w = 2:  155 chains, 77.5 and 85.25 give 78 and 86
        for instantiation in Instantiation::ALL {
            let Instantiation::TargetSum { target, .. } = instantiation else {
                continue;
            };
            let scheme = instantiation.scheme();
            let twice_expected = scheme.dimension * (scheme.base - 1);
            let wanted = match target {
                Target::Expected => twice_expected.div_ceil(2),
                Target::TenPercentAbove => (11 * twice_expected).div_ceil(20),
            };
            assert_eq!(scheme.target_sum, wanted, "{instantiation:?}");
        }
    }
}
