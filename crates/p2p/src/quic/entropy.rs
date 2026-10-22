//! Randomness for connection ids and TLS secrets: ChaCha20 with fast key erasure.
//!
//! The caller seeds the generator once with 32 bytes of operating system entropy.
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

use axiom_crypto::chacha20poly1305::ChaCha20;

/// Bytes of the key, and of each draw.
const KEY_LEN: usize = 32;

/// A forward-secure generator.
pub struct Entropy {
    /// The current key, replaced on every draw.
    key: [u8; KEY_LEN],
}

impl Entropy {
    /// A generator from a seed of operating system entropy.
    #[must_use]
    pub const fn new(seed: [u8; KEY_LEN]) -> Self {
        Self { key: seed }
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
