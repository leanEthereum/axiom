//! Reasons a scrypt parameter set or derivation is refused.

use thiserror::Error;

use crate::pbkdf2::Pbkdf2Error;

/// A scrypt parameter set outside RFC 7914, section 2, or above the memory cap.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ScryptError {
    /// The cost N is not a power of two.
    #[error("cost {n} is not a power of two")]
    CostNotPowerOfTwo {
        /// Cost requested.
        n: u64,
    },

    /// The cost N is not larger than 1.
    #[error("cost {n} is below the scrypt minimum of {min}")]
    CostTooSmall {
        /// Cost requested.
        n: u64,
        /// Smallest cost allowed.
        min: u64,
    },

    /// The cost N is not below 2^(16 r), the bound tied to the block size.
    #[error("cost 2^{log_n} exceeds the limit of 2^{max_log_n} for block size {r}")]
    CostTooLarge {
        /// Base-2 logarithm of the cost requested.
        log_n: u8,
        /// Base-2 logarithm of the largest cost allowed: 16 r - 1.
        max_log_n: u64,
        /// Block size requested.
        r: u32,
    },

    /// The block size r is zero.
    #[error("block size {r} is below the scrypt minimum of {min}")]
    BlockSizeTooSmall {
        /// Block size requested.
        r: u32,
        /// Smallest block size allowed.
        min: u32,
    },

    /// The parallelization p is zero.
    #[error("parallelization {p} is below the scrypt minimum of {min}")]
    ParallelismTooSmall {
        /// Parallelization requested.
        p: u32,
        /// Smallest parallelization allowed.
        min: u32,
    },

    /// The parallelization p exceeds (2^32 - 1) * 32 / (128 r).
    #[error("parallelization {p} exceeds the limit of {max} for block size {r}")]
    ParallelismTooLarge {
        /// Parallelization requested.
        p: u32,
        /// Largest parallelization allowed.
        max: u64,
        /// Block size requested.
        r: u32,
    },

    /// The working memory 128 r (N + p) exceeds the cap.
    #[error("working memory of {bytes} bytes exceeds the scrypt cap of {max}")]
    MemoryTooLarge {
        /// Bytes the parameters need, saturated at the largest 128-bit value.
        bytes: u128,
        /// Most bytes one derivation may use.
        max: u64,
    },

    /// The derived key is longer than the final PBKDF2 can produce.
    #[error("derived key: {0}")]
    Output(#[from] Pbkdf2Error),
}
