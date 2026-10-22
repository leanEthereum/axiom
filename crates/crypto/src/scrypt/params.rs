//! A validated scrypt parameter set, and the derivation it runs.

use sha2::Sha256;

use super::{ScryptError, romix::RoMix};
use crate::{ct::wipe, hmac::Hmac, pbkdf2::Pbkdf2};

/// Bytes in one scrypt block per unit of the block size r, per RFC 7914, section 2.
const BLOCK_BYTES_PER_R: u64 = 128;

/// Smallest block size and parallelization: both are positive integers, per RFC 7914, section 2.
const MIN_R_AND_P: u32 = 1;

/// Smallest cost: N must be larger than 1, per RFC 7914, section 2.
const MIN_N: u64 = 2;

/// The cost N, block size r, and parallelization p of one scrypt derivation.
///
/// # Invariants
///
/// - N is a power of two, larger than 1, and below 2^(16 r).
/// - r and p are positive, and p is at most (2^32 - 1) * 32 / (128 r).
/// - The working memory 128 r (N + p) is at most the cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScryptParams {
    /// Base-2 logarithm of the cost N.
    log_n: u8,
    /// Block size r: one block is 128 r bytes.
    r: u32,
    /// Parallelization p: the number of independent blocks.
    p: u32,
}

impl ScryptParams {
    /// Most working memory one derivation may use: 1 GiB.
    ///
    /// EIP-2335 keystores use N = 2^18, r = 8, p = 1, which needs 256 MiB.
    /// The cap admits that with fourfold headroom.
    /// It also bounds what a hostile keystore can make a node allocate.
    pub const MAX_MEMORY: u64 = 1 << 30;

    /// Parameters with cost N = 2^log_n.
    ///
    /// # Errors
    ///
    /// Fails when the set breaks RFC 7914, section 2, or needs more memory than the cap.
    pub fn new(log_n: u8, r: u32, p: u32) -> Result<Self, ScryptError> {
        // N > 1: the table needs at least two entries.
        if log_n == 0 {
            return Err(ScryptError::CostTooSmall { n: 1, min: MIN_N });
        }
        if r < MIN_R_AND_P {
            return Err(ScryptError::BlockSizeTooSmall {
                r,
                min: MIN_R_AND_P,
            });
        }
        if p < MIN_R_AND_P {
            return Err(ScryptError::ParallelismTooSmall {
                p,
                min: MIN_R_AND_P,
            });
        }

        // N < 2^(128 r / 8) = 2^(16 r): Integerify reads a 64-byte block, so N must fit in it.
        let max_log_n = 16 * u64::from(r) - 1;
        if u64::from(log_n) > max_log_n {
            return Err(ScryptError::CostTooLarge {
                log_n,
                max_log_n,
                r,
            });
        }

        // p * 128 r <= (2^32 - 1) * 32: the first PBKDF2 output fits its 32-bit block index.
        let max_p = u64::from(u32::MAX) * 32 / (BLOCK_BYTES_PER_R * u64::from(r));
        if u64::from(p) > max_p {
            return Err(ScryptError::ParallelismTooLarge { p, max: max_p, r });
        }

        // Memory: the table of N blocks plus the p blocks, of 128 r bytes each.
        // A cost of 2^128 or more saturates rather than wrapping.
        let bytes = 1_u128
            .checked_shl(u32::from(log_n))
            .and_then(|n| n.checked_add(u128::from(p)))
            .and_then(|blocks| blocks.checked_mul(u128::from(BLOCK_BYTES_PER_R * u64::from(r))))
            .unwrap_or(u128::MAX);
        if bytes > u128::from(Self::MAX_MEMORY) {
            return Err(ScryptError::MemoryTooLarge {
                bytes,
                max: Self::MAX_MEMORY,
            });
        }

        Ok(Self { log_n, r, p })
    }

    /// Parameters with cost N given directly, as keystores store it.
    ///
    /// # Errors
    ///
    /// Fails when N is not a power of two, or as the logarithmic form does.
    pub fn from_n(n: u64, r: u32, p: u32) -> Result<Self, ScryptError> {
        if !n.is_power_of_two() {
            return Err(ScryptError::CostNotPowerOfTwo { n });
        }
        // Invariant: a power of two in a u64 has at most 63 trailing zeros, so it fits a u8.
        Self::new(n.trailing_zeros() as u8, r, p)
    }

    /// The cost N.
    #[must_use]
    pub const fn n(&self) -> u64 {
        // Invariant: the memory cap holds log_n to at most 23, so the shift is in range.
        1 << self.log_n
    }

    /// The block size r.
    #[must_use]
    pub const fn r(&self) -> u32 {
        self.r
    }

    /// The parallelization p.
    #[must_use]
    pub const fn p(&self) -> u32 {
        self.p
    }

    /// Fills the output with scrypt key material, per RFC 7914, section 6.
    ///
    /// # Overview
    ///
    /// ```text
    /// B_0 || ... || B_(p - 1) = PBKDF2-HMAC-SHA256(P, S, 1, 128 r p)
    /// B_i                     = ROMix(B_i), for each i
    /// DK                      = PBKDF2-HMAC-SHA256(P, B_0 || ... || B_(p - 1), 1, dkLen)
    /// ```
    ///
    /// The p blocks run one after another and share one table.
    ///
    /// # Invariants
    ///
    /// The table lookups depend on the password, so memory access is not constant time.
    /// That is inherent to scrypt's memory hardness, per Percival 2009, section 5.
    ///
    /// # Errors
    ///
    /// Fails when the output is longer than (2^32 - 1) * 32 bytes.
    pub fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        output: &mut [u8],
    ) -> Result<(), ScryptError> {
        // Check the output before the memory-hard work, so a bad request fails fast.
        Pbkdf2::check::<Sha256>(1, output.len())?;

        // Both PBKDF2 calls key HMAC with the password: key it once.
        let prf = Hmac::<Sha256>::new(password);
        let block_len = BLOCK_BYTES_PER_R as usize * self.r as usize;

        // Step 1: expand the password into p blocks.
        let mut blocks = vec![0_u8; block_len * self.p as usize];
        Pbkdf2::fill(&prf, salt, 1, &mut blocks);

        // Step 2: mix each block through the shared table.
        let mut romix = RoMix::new(self.log_n, self.r as usize);
        for block in blocks.chunks_exact_mut(block_len) {
            romix.mix(block);
        }

        // Step 3: compress the mixed blocks into the derived key.
        Pbkdf2::fill(&prf, &blocks, 1, output);
        wipe(&mut blocks);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Derives 64 bytes, the length of every RFC 7914 scrypt vector.
    fn derive(password: &[u8], salt: &[u8], params: ScryptParams) -> Vec<u8> {
        let mut dk = vec![0; 64];
        params.derive(password, salt, &mut dk).unwrap();
        dk
    }

    #[test]
    fn rfc_7914_empty_password() {
        // RFC 7914, section 12: P = "", S = "", N = 16, r = 1, p = 1.
        let params = ScryptParams::from_n(16, 1, 1).unwrap();
        assert_eq!(
            derive(b"", b"", params),
            hex(concat!(
                "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442",
                "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            ))
        );
    }

    #[test]
    fn rfc_7914_sixteen_parallel_blocks() {
        // RFC 7914, section 12: P = "password", S = "NaCl", N = 1024, r = 8, p = 16.
        // Sixteen blocks of 1 KiB share one table of 1024 entries: 1 MiB.
        let params = ScryptParams::from_n(1024, 8, 16).unwrap();
        assert_eq!(
            derive(b"password", b"NaCl", params),
            hex(concat!(
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162",
                "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            ))
        );
    }

    #[test]
    fn rfc_7914_sixteen_mebibyte_table() {
        // RFC 7914, section 12: P = "pleaseletmein", S = "SodiumChloride", N = 16384, r = 8, p = 1.
        // The table holds 16384 blocks of 1 KiB: 16 MiB.
        //
        // The section's last vector, N = 1048576 with r = 8, needs a 1 GiB table.
        // It stays out of the unit tests to keep their memory small.
        let params = ScryptParams::from_n(16_384, 8, 1).unwrap();
        assert_eq!(
            derive(b"pleaseletmein", b"SodiumChloride", params),
            hex(concat!(
                "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2",
                "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            ))
        );
    }

    #[test]
    fn accessors_return_the_parameters() {
        // EIP-2335's keystore parameters: N = 2^18, r = 8, p = 1.
        let params = ScryptParams::new(18, 8, 1).unwrap();
        assert_eq!((params.n(), params.r(), params.p()), (262_144, 8, 1));
        assert_eq!(ScryptParams::from_n(262_144, 8, 1), Ok(params));
    }

    #[test]
    fn cost_must_be_a_power_of_two_above_one() {
        // 0 and 1000 are not powers of two.
        assert_eq!(
            ScryptParams::from_n(0, 1, 1),
            Err(ScryptError::CostNotPowerOfTwo { n: 0 })
        );
        assert_eq!(
            ScryptParams::from_n(1000, 1, 1),
            Err(ScryptError::CostNotPowerOfTwo { n: 1000 })
        );

        // 1 = 2^0 is a power of two, but a one-entry table is not memory-hard.
        assert_eq!(
            ScryptParams::from_n(1, 1, 1),
            Err(ScryptError::CostTooSmall { n: 1, min: 2 })
        );

        // 2 = 2^1 is the smallest cost accepted.
        assert_eq!(ScryptParams::from_n(2, 1, 1).map(|p| p.n()), Ok(2));
    }

    #[test]
    fn cost_must_stay_below_two_to_the_sixteen_r() {
        // Threshold: with r = 1, N < 2^16, so 2^15 passes and 2^16 fails.
        // Memory stays far below the cap: 128 * (2^16 + 1) bytes is about 8 MiB.
        assert_eq!(ScryptParams::new(15, 1, 1).map(|p| p.n()), Ok(32_768));
        assert_eq!(
            ScryptParams::new(16, 1, 1),
            Err(ScryptError::CostTooLarge {
                log_n: 16,
                max_log_n: 15,
                r: 1
            })
        );
    }

    #[test]
    fn block_size_and_parallelization_must_be_positive() {
        // r = 0 would make empty blocks; p = 0 would mix nothing.
        assert_eq!(
            ScryptParams::new(4, 0, 1),
            Err(ScryptError::BlockSizeTooSmall { r: 0, min: 1 })
        );
        assert_eq!(
            ScryptParams::new(4, 1, 0),
            Err(ScryptError::ParallelismTooSmall { p: 0, min: 1 })
        );
    }

    #[test]
    fn parallelization_limit() {
        // Threshold: with r = 2^20, p <= (2^32 - 1) * 32 / 2^27 = 1023.
        // Mutation: p = 1024 crosses it, before the memory check runs.
        assert_eq!(
            ScryptParams::new(1, 1 << 20, 1024),
            Err(ScryptError::ParallelismTooLarge {
                p: 1024,
                max: 1023,
                r: 1 << 20
            })
        );
    }

    #[test]
    fn memory_cap() {
        // Threshold: 2^30 bytes.
        //
        //     N = 2^20, r = 8, p = 1: 1024 * (2^20 + 1) = 2^30 + 1024 bytes, refused
        //     N = 2^19, r = 8, p = 1: 1024 * (2^19 + 1) = 2^29 + 1024 bytes, accepted
        assert_eq!(
            ScryptParams::new(20, 8, 1),
            Err(ScryptError::MemoryTooLarge {
                bytes: (1 << 30) + 1024,
                max: 1 << 30
            })
        );
        assert_eq!(ScryptParams::new(19, 8, 1).map(|p| p.n()), Ok(1 << 19));

        // A cost of 2^200 overflows 128 bits, so the requested size saturates.
        assert_eq!(
            ScryptParams::new(200, 16, 1),
            Err(ScryptError::MemoryTooLarge {
                bytes: u128::MAX,
                max: 1 << 30
            })
        );
    }
}
