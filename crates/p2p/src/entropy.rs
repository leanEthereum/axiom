//! Randomness for handshake secrets and connection ids: ChaCha20 with fast key erasure.
//!
//! The generator is seeded once with 32 bytes of operating system entropy.
//! Each draw takes one 64-byte ChaCha20 block:
//!
//! ```text
//! block   = ChaCha20(k_i, nonce 0, counter 0)
//! k_{i+1} = block[0..32]     replaces the key at once
//! output  = block[32..64]
//! ```
//!
//! Overwriting the key on every draw keeps past outputs safe if the state leaks later.
//! See D. J. Bernstein, "Fast-key-erasure random-number generators", 2017.

use std::{
    fs::File,
    io::{self, Read},
};

use axiom_crypto::chacha20poly1305::ChaCha20;

/// Bytes of the key, and of each draw.
const KEY_LEN: usize = 32;

/// Path of the kernel's non-blocking entropy device.
const ENTROPY_DEVICE: &str = "/dev/urandom";

/// A forward-secure generator.
pub struct Entropy {
    /// The current key, replaced on every draw.
    key: [u8; KEY_LEN],
}

impl Entropy {
    /// A generator from a seed; equal seeds draw equal streams, so tests use it.
    #[must_use]
    pub const fn new(seed: [u8; KEY_LEN]) -> Self {
        Self { key: seed }
    }

    /// A generator seeded from the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Fails when the entropy device cannot be read.
    pub fn from_os() -> io::Result<Self> {
        let mut seed = [0; KEY_LEN];
        File::open(ENTROPY_DEVICE)?.read_exact(&mut seed)?;
        Ok(Self::new(seed))
    }

    /// Draws 32 bytes and erases the key that produced them.
    fn draw(&mut self) -> [u8; KEY_LEN] {
        let mut block = [0u8; 2 * KEY_LEN];
        ChaCha20::new(&self.key, &[0; 12], 0).apply_keystream(&mut block);
        self.key.copy_from_slice(&block[..KEY_LEN]);
        let mut output = [0u8; KEY_LEN];
        output.copy_from_slice(&block[KEY_LEN..]);
        block.fill(0);
        output
    }

    /// Fills a buffer with random bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(KEY_LEN) {
            let mut draw = self.draw();
            chunk.copy_from_slice(&draw[..chunk.len()]);
            draw.fill(0);
        }
    }

    /// A random array.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.fill(&mut out);
        out
    }
}

impl Drop for Entropy {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl core::fmt::Debug for Entropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entropy").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn draws_follow_the_rfc_8439_keystream() {
        // With the all-zero key, block 0 is the RFC 8439 appendix A.1 test vector 1.
        // Its first 32 bytes become the key; its last 32 bytes are the output.
        let mut entropy = Entropy::new([0; 32]);
        assert_eq!(
            entropy.array::<32>().to_vec(),
            hex("da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
        );
        assert_eq!(
            entropy.key.to_vec(),
            hex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7")
        );
    }

    #[test]
    fn operating_system_seeds_differ() {
        // Two seeds from the entropy device collide with probability 2^-256.
        let a: [u8; 32] = Entropy::from_os().unwrap().array();
        let b: [u8; 32] = Entropy::from_os().unwrap().array();
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_per_seed_and_never_repeating() {
        let mut a = Entropy::new([1; 32]);
        let mut b = Entropy::new([1; 32]);
        let first: [u8; 40] = a.array();
        assert_eq!(first, b.array::<40>());
        // The next draw differs from the first: the key moved on.
        assert_ne!(first, a.array::<40>());
        // Another seed gives another stream.
        assert_ne!(first, Entropy::new([2; 32]).array::<40>());
    }
}
