//! PBKDF2, the iterated password-based key derivation of RFC 8018, section 5.2.

use sha2::{
    Sha256, Sha512,
    digest::{Digest, OutputSizeUser, core_api::BlockSizeUser},
};
use thiserror::Error;

use crate::{ct::wipe, hmac::Hmac};

/// Fewest iterations RFC 8018, section 5.2, admits: the count is a positive integer.
const MIN_ITERATIONS: u32 = 1;

/// PBKDF2 over HMAC, stretching a password and salt into key material.
///
/// # Overview
///
/// ```text
/// T_i = U_1 ^ U_2 ^ ... ^ U_c
/// U_1 = HMAC(P, S || INT(i))
/// U_j = HMAC(P, U_(j - 1))
/// DK  = first dkLen bytes of T_1 || T_2 || ...
/// ```
///
/// INT(i) is the block index as four big-endian bytes, starting at 1.
///
/// # Performance
///
/// The password keys the inner and outer hashes once.
/// Each iteration clones those midstates, so it costs two compressions and no key hashing.
#[derive(Clone, Copy, Debug)]
pub struct Pbkdf2;

impl Pbkdf2 {
    /// Fills the output with PBKDF2-HMAC-SHA256 key material.
    ///
    /// # Errors
    ///
    /// Fails on zero iterations, or on an output longer than (2^32 - 1) * 32 bytes.
    pub fn sha256(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), Pbkdf2Error> {
        Self::derive::<Sha256>(password, salt, iterations, output)
    }

    /// Fills the output with PBKDF2-HMAC-SHA512 key material.
    ///
    /// # Errors
    ///
    /// Fails on zero iterations, or on an output longer than (2^32 - 1) * 64 bytes.
    pub fn sha512(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), Pbkdf2Error> {
        Self::derive::<Sha512>(password, salt, iterations, output)
    }

    /// Checks the request, then derives.
    fn derive<H: Digest + BlockSizeUser + Clone>(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), Pbkdf2Error> {
        Self::check::<H>(iterations, output.len())?;
        Self::fill(&Hmac::<H>::new(password), salt, iterations, output);
        Ok(())
    }

    /// Checks an iteration count and output length against RFC 8018, section 5.2.
    ///
    /// The output holds at most 2^32 - 1 blocks, since the block index is a 32-bit counter from 1.
    pub(crate) fn check<H: OutputSizeUser>(iterations: u32, len: usize) -> Result<(), Pbkdf2Error> {
        if iterations < MIN_ITERATIONS {
            return Err(Pbkdf2Error::TooFewIterations {
                iterations,
                min: MIN_ITERATIONS,
            });
        }
        // Step 1: dkLen > (2^32 - 1) * hLen is "derived key too long".
        let max = u64::from(u32::MAX) * H::output_size() as u64;
        let len = len as u64;
        if len > max {
            return Err(Pbkdf2Error::OutputTooLong { len, max });
        }
        Ok(())
    }

    /// Fills the output under a password already keyed into the pseudorandom function.
    ///
    /// # Invariants
    ///
    /// The request has passed the iteration and length check: c >= 1 and at most 2^32 - 1 blocks.
    pub(crate) fn fill<H: Digest + BlockSizeUser + Clone>(
        prf: &Hmac<H>,
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) {
        // Invariant: the caller bounds the output, so the 32-bit index never runs out first.
        let block_len = <H as OutputSizeUser>::output_size();
        for (index, chunk) in (1_u32..).zip(output.chunks_mut(block_len)) {
            // U_1 = PRF(P, S || INT(i)).
            let mut mac = prf.clone();
            mac.update(salt);
            mac.update(&index.to_be_bytes());
            let mut u = mac.finalize();
            let mut t = u.clone();

            // U_j = PRF(P, U_(j - 1)), folded into T by XOR.
            // Every step restarts from the keyed midstates, never from the password.
            for _ in 1..iterations {
                let mut mac = prf.clone();
                mac.update(&u);
                u = mac.finalize();
                for (acc, byte) in t.iter_mut().zip(&u) {
                    *acc ^= byte;
                }
            }

            // The last block may be cut short to the requested length.
            chunk.copy_from_slice(&t[..chunk.len()]);

            // Both blocks reveal output bytes: clear them.
            wipe(u.as_mut_slice());
            wipe(t.as_mut_slice());
        }
    }
}

/// A key derivation request PBKDF2 cannot serve.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Pbkdf2Error {
    /// The iteration count is below the minimum of RFC 8018, section 5.2.
    #[error("iteration count {iterations} is below the PBKDF2 minimum of {min}")]
    TooFewIterations {
        /// Iterations requested.
        iterations: u32,
        /// Fewest iterations allowed.
        min: u32,
    },

    /// The requested output exceeds 2^32 - 1 hash blocks.
    #[error("output of {len} bytes exceeds the PBKDF2 limit of {max}")]
    OutputTooLong {
        /// Bytes requested.
        len: u64,
        /// Most bytes one derivation produces.
        max: u64,
    },
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc_7914_sha256_one_iteration() {
        // RFC 7914, section 11: P = "passwd", S = "salt", c = 1, dkLen = 64.
        // 64 bytes span two 32-byte blocks, so the block index reaches 2.
        let mut dk = [0_u8; 64];
        Pbkdf2::sha256(b"passwd", b"salt", 1, &mut dk).unwrap();
        assert_eq!(
            dk.to_vec(),
            hex(concat!(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ))
        );
    }

    #[test]
    fn rfc_7914_sha256_eighty_thousand_iterations() {
        // RFC 7914, section 11: P = "Password", S = "NaCl", c = 80000, dkLen = 64.
        let mut dk = [0_u8; 64];
        Pbkdf2::sha256(b"Password", b"NaCl", 80_000, &mut dk).unwrap();
        assert_eq!(
            dk.to_vec(),
            hex(concat!(
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56",
                "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            ))
        );
    }

    #[test]
    fn zero_iterations_are_refused() {
        // RFC 8018 requires a positive count: 0 iterations would output nothing derived.
        assert_eq!(
            Pbkdf2::sha256(b"p", b"s", 0, &mut [0; 32]),
            Err(Pbkdf2Error::TooFewIterations {
                iterations: 0,
                min: 1
            })
        );
        assert_eq!(
            Pbkdf2::sha512(b"p", b"s", 0, &mut [0; 64]),
            Err(Pbkdf2Error::TooFewIterations {
                iterations: 0,
                min: 1
            })
        );
    }

    #[test]
    fn output_length_limit_per_hash() {
        // Threshold: 2^32 - 1 blocks of hLen bytes.
        //
        //     SHA-256: 4294967295 * 32 = 137438953440
        //     SHA-512: 4294967295 * 64 = 274877906880
        //
        // Buffers that large cannot be allocated in a test, so the check runs on the length alone.
        assert_eq!(Pbkdf2::check::<Sha256>(1, 137_438_953_440), Ok(()));
        assert_eq!(
            Pbkdf2::check::<Sha256>(1, 137_438_953_441),
            Err(Pbkdf2Error::OutputTooLong {
                len: 137_438_953_441,
                max: 137_438_953_440
            })
        );
        assert_eq!(Pbkdf2::check::<Sha512>(1, 274_877_906_880), Ok(()));
        assert_eq!(
            Pbkdf2::check::<Sha512>(1, 274_877_906_881),
            Err(Pbkdf2Error::OutputTooLong {
                len: 274_877_906_881,
                max: 274_877_906_880
            })
        );
    }

    #[test]
    fn empty_output_is_a_no_op() {
        // Zero bytes requested: no block runs and nothing fails.
        assert_eq!(Pbkdf2::sha512(b"p", b"s", 1, &mut []), Ok(()));
    }

    proptest! {
        #[test]
        fn shorter_outputs_are_prefixes(
            len in 0_usize..200,
            salt in prop::collection::vec(any::<u8>(), 0..40),
        ) {
            // Blocks depend only on their index, so a shorter output cuts the longer one.
            let mut long = [0_u8; 200];
            Pbkdf2::sha256(b"password", &salt, 3, &mut long).unwrap();
            let mut short = vec![0_u8; len];
            Pbkdf2::sha256(b"password", &salt, 3, &mut short).unwrap();
            prop_assert_eq!(&short[..], &long[..len]);

            Pbkdf2::sha512(b"password", &salt, 3, &mut long).unwrap();
            Pbkdf2::sha512(b"password", &salt, 3, &mut short).unwrap();
            prop_assert_eq!(&short[..], &long[..len]);
        }
    }
}
