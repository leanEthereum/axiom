//! A BLS key held in this process's memory.

use std::fmt;

use axiom_bls::SecretKey;
use axiom_types::{BlsPubkey, BlsSignature, Root};

/// A BLS secret key in memory, with its public key.
///
/// Signing is BLS12-381 with proof of possession, as the phase0 beacon chain spec defines it.
/// See draft-irtf-cfrg-bls-signature-05.
pub struct LocalKey {
    /// The secret key.
    secret: SecretKey,
    /// Its public key, derived once.
    public: BlsPubkey,
}

impl LocalKey {
    /// A key from its secret.
    #[must_use]
    pub fn new(secret: SecretKey) -> Self {
        Self {
            public: BlsPubkey(secret.public_key().to_bytes()),
            secret,
        }
    }

    /// The public key.
    #[must_use]
    pub const fn public_key(&self) -> &BlsPubkey {
        &self.public
    }

    /// Signs a signing root.
    #[must_use]
    pub fn sign(&self, root: Root) -> BlsSignature {
        BlsSignature(self.secret.sign(&root.0).to_bytes())
    }
}

impl fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret never prints; the public key names the validator.
        f.debug_struct("LocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::{PublicKey, Signature};

    use super::*;

    #[test]
    fn a_key_signs_a_root_deterministically() {
        // Fixture state: the secret key 1 signs the root 0x2a...2a twice.
        let mut bytes = [0; 32];
        bytes[31] = 1;
        let key = LocalKey::new(SecretKey::from_bytes(&bytes).unwrap());
        let first = key.sign(Root([42; 32]));
        let second = key.sign(Root([42; 32]));

        // BLS signing is deterministic: the same root gives the same signature.
        assert_eq!(first, second);

        // The signature verifies over its root under the key, and over no other root.
        let public = PublicKey::from_bytes(&key.public_key().0).unwrap();
        let signature = Signature::from_bytes(&first.0).unwrap();
        assert!(signature.verify(&public, &[42; 32]));
        assert!(!signature.verify(&public, &[43; 32]));
    }
}
