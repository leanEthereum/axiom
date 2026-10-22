//! Fresh randomness from the operating system, for mnemonics, salts, IVs, and UUIDs.

use std::{
    fs::File,
    io::{self, Read},
};

/// The operating system's entropy source.
///
/// Every call reads the kernel generator afresh, so no secret state lives in the process.
#[derive(Clone, Copy, Debug)]
pub struct OsEntropy;

impl OsEntropy {
    /// The kernel's generator, which never blocks once seeded at boot.
    const SOURCE: &'static str = "/dev/urandom";

    /// Fills a buffer with fresh random bytes.
    ///
    /// # Errors
    ///
    /// Fails when the entropy source cannot be opened or read.
    pub fn fill(out: &mut [u8]) -> io::Result<()> {
        File::open(Self::SOURCE)?.read_exact(out)
    }

    /// A fresh array of random bytes.
    ///
    /// # Errors
    ///
    /// Fails when the entropy source cannot be opened or read.
    pub fn array<const N: usize>() -> io::Result<[u8; N]> {
        let mut out = [0; N];
        Self::fill(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_draws_differ() {
        // Two 32-byte draws collide with probability 2^-256.
        let first: [u8; 32] = OsEntropy::array().unwrap();
        let second: [u8; 32] = OsEntropy::array().unwrap();
        assert_ne!(first, second);
    }
}
