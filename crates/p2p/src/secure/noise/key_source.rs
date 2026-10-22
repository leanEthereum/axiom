//! The source of X25519 secrets: a ChaCha20 generator with fast key erasure.
//!
//! ```text
//! seed key k0 (32 bytes from the operating system)
//!
//! draw:  block = ChaCha20(k_i, nonce 0, counter 0), 64 bytes
//!        k_{i+1} = block[0..32]     replaces the key at once
//!        secret  = block[32..64]    handed out
//! ```
//!
//! Overwriting the key on every draw keeps past secrets safe if the state leaks later.
//! See D. J. Bernstein, "Fast-key-erasure random-number generators", 2017.

use std::{fs::File, io, io::Read};

use axiom_crypto::{chacha20poly1305::ChaCha20, x25519::SecretKey};

/// Path of the kernel's non-blocking entropy device.
const ENTROPY_DEVICE: &str = "/dev/urandom";

/// Bytes of the generator key, and of every secret drawn.
const KEY_LEN: usize = 32;

/// A forward-secure generator of Diffie-Hellman secrets.
pub(super) struct KeySource {
    /// The current ChaCha20 key, replaced on every draw.
    key: [u8; KEY_LEN],
}

impl KeySource {
    /// A generator seeded from the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Fails when the entropy device cannot be read.
    pub(super) fn from_os() -> io::Result<Self> {
        let mut key = [0u8; KEY_LEN];
        File::open(ENTROPY_DEVICE)?.read_exact(&mut key)?;
        Ok(Self { key })
    }

    /// A generator from a fixed seed: equal seeds draw equal secrets.
    pub(super) const fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        Self { key: seed }
    }

    /// Draws the next secret and erases the key that produced it.
    pub(super) fn next_secret(&mut self) -> SecretKey {
        // One 64-byte block of keystream: the key stream over zeros.
        let mut block = [0u8; 2 * KEY_LEN];
        ChaCha20::new(&self.key, &[0; 12], 0).apply_keystream(&mut block);

        // Phase 1: the first half becomes the next key.
        self.key.copy_from_slice(&block[..KEY_LEN]);

        // Phase 2: the second half is the secret.
        let mut secret = [0u8; KEY_LEN];
        secret.copy_from_slice(&block[KEY_LEN..]);
        block.fill(0);
        SecretKey::from_bytes(secret)
    }
}

impl Drop for KeySource {
    fn drop(&mut self) {
        // The key predicts every future secret.
        self.key.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn draws_follow_the_rfc_8439_keystream() {
        // With the all-zero key, block 0 is the RFC 8439 appendix A.1 test vector 1.
        // Its first 32 bytes become the key; its last 32 bytes are the secret.
        let mut source = KeySource::from_seed([0; 32]);
        let first = source.next_secret();
        assert_eq!(
            first.to_bytes().to_vec(),
            hex("da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
        );
        assert_eq!(
            source.key.to_vec(),
            hex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7")
        );
    }

    #[test]
    fn successive_draws_differ() {
        // Two draws from one seed, and one draw from another seed, are pairwise distinct.
        let mut source = KeySource::from_seed([1; 32]);
        let a = source.next_secret().to_bytes();
        let b = source.next_secret().to_bytes();
        let c = KeySource::from_seed([2; 32]).next_secret().to_bytes();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn operating_system_seeds_differ() {
        // Two seeds from the entropy device collide with probability 2^-256.
        let a = KeySource::from_os().unwrap().next_secret().to_bytes();
        let b = KeySource::from_os().unwrap().next_secret().to_bytes();
        assert_ne!(a, b);
    }
}
