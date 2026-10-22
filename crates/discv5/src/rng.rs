//! A seeded generator for nonces, masking vectors, and ephemeral keys.

use std::fmt;

use axiom_crypto::secp256k1::SecretKey;
use sha2::{Digest, Sha256};

/// SHA-256 in counter mode over a 32-byte seed.
///
/// # Overview
///
/// ```text
/// block i = SHA-256(seed || i as 8 little-endian bytes)
/// ```
///
/// The output is unpredictable to anyone without the seed, as long as SHA-256 is a PRF.
/// The service stays pure: the driver seeds it from the operating system.
/// Simulations seed it with a constant and replay exactly.
#[derive(Clone)]
pub struct Csprng {
    /// The secret seed.
    seed: [u8; 32],
    /// Index of the next block.
    counter: u64,
    /// Unused bytes of the current block.
    buffer: [u8; 32],
    /// Bytes of the buffer already handed out.
    used: usize,
}

impl Csprng {
    /// A generator from a seed; equal seeds give equal streams.
    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0; 32],
            used: 32,
        }
    }

    /// Fills a buffer with fresh bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            // Refill: hash the seed with the next counter.
            if self.used == self.buffer.len() {
                let mut hasher = Sha256::new();
                hasher.update(self.seed);
                hasher.update(self.counter.to_le_bytes());
                self.buffer = hasher.finalize().into();
                self.counter += 1;
                self.used = 0;
            }
            *byte = self.buffer[self.used];
            self.used += 1;
        }
    }

    /// A fresh array of bytes.
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.fill(&mut out);
        out
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes())
    }

    /// A value below a positive bound.
    pub fn below(&mut self, bound: usize) -> usize {
        // Lemire's multiply-shift maps 64 bits onto the range with negligible bias.
        ((u128::from(self.next_u64()) * bound as u128) >> 64) as usize
    }

    /// A fresh secp256k1 secret key.
    pub fn secret_key(&mut self) -> SecretKey {
        // Rejection sampling: a 32-byte string falls outside [1, n) with probability about 2^-128.
        loop {
            if let Ok(key) = SecretKey::from_bytes(&self.bytes()) {
                return key;
            }
        }
    }
}

impl fmt::Debug for Csprng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The seed is secret: never print it.
        f.debug_struct("Csprng").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_are_reproducible_and_split_freely() {
        // Two generators from seed 7 agree on 100 bytes.
        let mut a = Csprng::from_seed([7; 32]);
        let mut b = Csprng::from_seed([7; 32]);
        let whole: [u8; 100] = a.bytes();
        // Reading 30 then 70 bytes gives the same stream as 100 at once.
        let head: [u8; 30] = b.bytes();
        let tail: [u8; 70] = b.bytes();
        assert_eq!(whole[..30], head);
        assert_eq!(whole[30..], tail);
        // Another seed gives another stream.
        let other: [u8; 100] = Csprng::from_seed([8; 32]).bytes();
        assert_ne!(whole, other);
        // Bounded draws stay in range.
        for _ in 0..1000 {
            assert!(a.below(13) < 13);
        }
    }
}
