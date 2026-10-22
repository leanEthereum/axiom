//! The random values one handshake consumes.

use std::{fmt, hint::black_box};

use axiom_crypto::hkdf::Hkdf;

/// Every random value of one handshake, drawn by the caller.
///
/// The pure handshake never reads the operating system, so the caller supplies these.
/// Tests set them to reproduce published traces.
#[derive(Clone, PartialEq, Eq)]
pub struct Randomness {
    /// The hello random.
    pub random: [u8; 32],
    /// The legacy session id a TCP client sends, for middlebox compatibility.
    pub session_id: [u8; 32],
    /// The X25519 key share secret.
    pub x25519: [u8; 32],
    /// The P-256 key share secret.
    pub p256: [u8; 32],
    /// The RSA-PSS salt, of which a signature takes as many bytes as its hash.
    pub salt: [u8; 64],
}

impl Randomness {
    /// Expands a 32-byte seed of operating system entropy into every value.
    ///
    /// # Algorithm
    ///
    /// HKDF-Expand over SHA-256 with a distinct label per value, per RFC 5869, section 2.3.
    /// With a uniform seed as the pseudorandom key, the outputs are independent and uniform.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let hkdf = Hkdf::from_prk(seed);
        let mut random = Self {
            random: [0; 32],
            session_id: [0; 32],
            x25519: [0; 32],
            p256: [0; 32],
            salt: [0; 64],
        };
        let outputs: [(&[u8], &mut [u8]); 5] = [
            (b"axiom tls random", &mut random.random),
            (b"axiom tls session id", &mut random.session_id),
            (b"axiom tls x25519", &mut random.x25519),
            (b"axiom tls p256", &mut random.p256),
            (b"axiom tls salt", &mut random.salt),
        ];
        for (label, out) in outputs {
            // Invariant: every output is at most 64 bytes, far below the 8160-byte bound.
            hkdf.expand(label, out)
                .expect("output within the HKDF bound");
        }
        random
    }
}

impl Drop for Randomness {
    fn drop(&mut self) {
        // The key share secrets and salt are secret until the handshake has used them.
        self.x25519.fill(0);
        self.p256.fill(0);
        self.salt.fill(0);
        black_box(&mut self.x25519);
        black_box(&mut self.p256);
        black_box(&mut self.salt);
    }
}

impl fmt::Debug for Randomness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Randomness").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_expand_deterministically_and_apart() {
        let a = Randomness::from_seed([1; 32]);
        let b = Randomness::from_seed([1; 32]);
        let c = Randomness::from_seed([2; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Distinct labels give distinct values from one seed.
        assert_ne!(a.random, a.x25519);
        assert_ne!(a.x25519, a.p256);
    }
}
