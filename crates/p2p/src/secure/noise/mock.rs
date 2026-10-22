//! Insecure stand-ins for the Noise primitives, for tests only.
//!
//! # Overview
//!
//! They keep the algebra the handshake relies on, without any security.
//!
//! - DH is exponentiation modulo the Mersenne prime p = 2^61 - 1.
//!   It commutes: (g^a)^b = (g^b)^a.
//! - The AEAD is a SHA-256 keystream with a SHA-256 tag.
//!   A wrong key, nonce, or bit flip fails the tag check.
//! - A signature is SHA-256(key || message), which anyone can forge.

use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use super::{DH_LEN, DhKeypair, NoiseCrypto, NoiseIdentity, TAG_LEN};
use crate::{identity::PublicKey, secure::SecureError};

/// The modulus 2^61 - 1.
const P: u64 = (1 << 61) - 1;

/// The base of the exponentiation.
const G: u64 = 3;

/// Modular exponentiation by squaring.
fn pow_mod(base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u128;
    let mut square = u128::from(base % P);
    // Walk the exponent bits from least significant up.
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * square % u128::from(P);
        }
        square = square * square % u128::from(P);
        exponent >>= 1;
    }
    // Invariant: the result is reduced modulo p < 2^61.
    result as u64
}

/// Insecure DH and AEAD with a deterministic key source.
#[derive(Debug)]
pub(crate) struct MockCrypto {
    /// Counter feeding key generation.
    counter: AtomicU64,
}

impl MockCrypto {
    /// Primitives whose keys derive from a seed.
    pub(crate) const fn new(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(seed << 32),
        }
    }

    /// The keystream byte block for a position.
    fn keystream(key: &[u8; 32], nonce: u64, block: u64) -> [u8; 32] {
        Sha256::new()
            .chain_update(key)
            .chain_update(nonce.to_le_bytes())
            .chain_update(block.to_le_bytes())
            .finalize()
            .into()
    }

    /// The tag over associated data and ciphertext.
    fn tag(key: &[u8; 32], nonce: u64, ad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
        let digest = Sha256::new()
            .chain_update(b"tag")
            .chain_update(key)
            .chain_update(nonce.to_le_bytes())
            .chain_update((ad.len() as u64).to_le_bytes())
            .chain_update(ad)
            .chain_update(ciphertext)
            .finalize();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&digest[..TAG_LEN]);
        tag
    }

    /// XORs data with the keystream.
    fn apply(key: &[u8; 32], nonce: u64, data: &[u8], out: &mut Vec<u8>) {
        for (index, chunk) in data.chunks(32).enumerate() {
            let stream = Self::keystream(key, nonce, index as u64);
            out.extend(chunk.iter().zip(stream).map(|(byte, key)| byte ^ key));
        }
    }
}

impl NoiseCrypto for MockCrypto {
    fn generate_keypair(&self) -> DhKeypair {
        // A distinct exponent per call, never zero.
        let exponent = self.counter.fetch_add(1, Ordering::Relaxed) % (P - 2) + 1;
        let mut secret = [0u8; 32];
        secret[..8].copy_from_slice(&exponent.to_le_bytes());
        let mut public = [0u8; DH_LEN];
        public[..8].copy_from_slice(&pow_mod(G, exponent).to_le_bytes());
        DhKeypair { secret, public }
    }

    fn dh(&self, secret: &[u8; 32], public: &[u8; DH_LEN]) -> Result<[u8; 32], SecureError> {
        let exponent = u64::from_le_bytes(
            secret[..8]
                .try_into()
                .map_err(|_| SecureError::InvalidKey)?,
        );
        let base = u64::from_le_bytes(
            public[..8]
                .try_into()
                .map_err(|_| SecureError::InvalidKey)?,
        );
        // Zero has no inverse and would leak a fixed shared secret.
        if base % P == 0 {
            return Err(SecureError::InvalidKey);
        }
        let mut shared = [0u8; 32];
        shared[..8].copy_from_slice(&pow_mod(base, exponent).to_le_bytes());
        Ok(shared)
    }

    fn encrypt(&self, key: &[u8; 32], nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        Self::apply(key, nonce, plaintext, out);
        let tag = Self::tag(key, nonce, ad, &out[start..]);
        out.extend_from_slice(&tag);
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        if Self::tag(key, nonce, ad, body) != tag {
            return Err(SecureError::DecryptionFailed);
        }
        Self::apply(key, nonce, body, out);
        Ok(())
    }
}

/// An insecure identity: a secp256k1-shaped key with a forgeable signature.
#[derive(Debug)]
pub(crate) struct MockIdentity {
    /// The announced key.
    key: PublicKey,
}

impl MockIdentity {
    /// An identity whose key bytes derive from a seed.
    pub(crate) fn new(seed: u8) -> Self {
        let mut compressed = [seed; 33];
        compressed[0] = 0x02;
        Self {
            key: PublicKey::secp256k1(compressed),
        }
    }

    /// The forgeable signature of a key over a message.
    fn signature(key: &PublicKey, message: &[u8]) -> Vec<u8> {
        Sha256::new()
            .chain_update(&key.data)
            .chain_update(message)
            .finalize()
            .to_vec()
    }
}

impl NoiseIdentity for MockIdentity {
    fn public_key(&self) -> PublicKey {
        self.key.clone()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        Self::signature(&self.key, message)
    }

    fn verify(&self, key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
        Self::signature(key, message) == signature
    }
}
