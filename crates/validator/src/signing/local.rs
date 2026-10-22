//! A key held in this process's memory.

use std::{fmt, sync::Arc};

use axiom_types::Root;
use thiserror::Error;

use crate::signing::{KeyState, LeafLedger, LedgerError, SchemeError, SignatureScheme};

/// A secret key in memory, with the ledger its leaves are spent from when the scheme needs one.
pub struct LocalKey<S: SignatureScheme> {
    /// The secret key.
    secret: S::SecretKey,
    /// Its public key, derived once.
    public: S::PublicKey,
    /// Where a stateful key records its spent leaves.
    ledger: Option<Arc<LeafLedger>>,
}

impl<S: SignatureScheme> LocalKey<S> {
    /// A key of a stateless scheme.
    ///
    /// # Errors
    ///
    /// Fails for a stateful scheme, whose key must not sign without a ledger.
    pub fn new(secret: S::SecretKey) -> Result<Self, LocalKeyError> {
        if let KeyState::OneTime { .. } = S::KEY_STATE {
            return Err(LocalKeyError::LedgerRequired { scheme: S::NAME });
        }
        Ok(Self {
            public: S::public_key(&secret),
            secret,
            ledger: None,
        })
    }

    /// A key that spends its leaves from a ledger, as a stateful scheme requires.
    #[must_use]
    pub fn with_ledger(secret: S::SecretKey, ledger: Arc<LeafLedger>) -> Self {
        Self {
            public: S::public_key(&secret),
            secret,
            ledger: Some(ledger),
        }
    }

    /// The public key.
    #[must_use]
    pub const fn public_key(&self) -> &S::PublicKey {
        &self.public
    }

    /// Signs a root, spending a leaf first when the scheme is stateful.
    ///
    /// # Errors
    ///
    /// Fails when the key's leaves run out, the ledger fails, or the scheme refuses.
    pub fn sign(&self, root: Root) -> Result<S::Signature, LocalKeyError> {
        let leaf = match (S::KEY_STATE, &self.ledger) {
            (KeyState::Stateless, _) => None,
            // The leaf is durably spent before the scheme ever sees it.
            (KeyState::OneTime { leaves }, Some(ledger)) => {
                Some(ledger.reserve(self.public.as_ref(), leaves)?)
            }
            (KeyState::OneTime { .. }, None) => {
                return Err(LocalKeyError::LedgerRequired { scheme: S::NAME });
            }
        };
        Ok(S::sign(&self.secret, leaf, root)?)
    }
}

impl<S: SignatureScheme> fmt::Debug for LocalKey<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret never prints; the public key names the validator.
        f.debug_struct("LocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Why a local key could not sign.
#[derive(Debug, Error)]
pub enum LocalKeyError {
    /// A stateful scheme's key has no ledger to spend leaves from.
    #[error("a {scheme} key signs only with a leaf ledger")]
    LedgerRequired {
        /// Name of the scheme.
        scheme: &'static str,
    },
    /// The ledger could not spend a leaf.
    #[error("leaf ledger: {0}")]
    Ledger(#[from] LedgerError),
    /// The scheme refused the request.
    #[error("signature scheme: {0}")]
    Scheme(#[from] SchemeError),
}

#[cfg(test)]
mod tests {
    use axiom_bls::SecretKey;
    use axiom_types::{BlsSignature, Root};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::signing::{Bls, Leaf};

    /// A toy one-time scheme with four leaves, standing in for a hash-based scheme.
    ///
    /// Its signature hashes the secret, the leaf, and the root, so it is no real scheme.
    /// It only checks that the seam spends a fresh leaf per signature.
    #[derive(Debug)]
    struct OneTimeToy;

    impl SignatureScheme for OneTimeToy {
        type SecretKey = [u8; 32];
        type PublicKey = [u8; 32];
        type Signature = ([u8; 32], u64);

        const NAME: &'static str = "toy";
        const KEY_STATE: KeyState = KeyState::OneTime { leaves: 4 };

        fn public_key(secret: &[u8; 32]) -> [u8; 32] {
            Sha256::digest(secret).into()
        }

        fn sign(
            secret: &[u8; 32],
            leaf: Option<Leaf>,
            root: Root,
        ) -> Result<([u8; 32], u64), SchemeError> {
            let leaf = leaf.ok_or(SchemeError::MissingLeaf { scheme: "toy" })?;
            let mut hash = Sha256::new();
            hash.update(secret);
            hash.update(leaf.0.to_be_bytes());
            hash.update(root.0);
            Ok((hash.finalize().into(), leaf.0))
        }

        fn verify(_: &[u8; 32], _: Option<Leaf>, _: Root, _: &([u8; 32], u64)) -> bool {
            false
        }

        fn aggregate(_: &[([u8; 32], u64)]) -> Option<([u8; 32], u64)> {
            None
        }
    }

    #[test]
    fn a_bls_key_signs_without_state() {
        // Fixture state: the secret key 1 signs the root 0x2a...2a twice.
        let mut bytes = [0; 32];
        bytes[31] = 1;
        let key = LocalKey::<Bls>::new(SecretKey::from_bytes(&bytes).unwrap()).unwrap();
        let first = key.sign(Root([42; 32])).unwrap();
        let second = key.sign(Root([42; 32])).unwrap();

        // BLS is deterministic and stateless: the same root gives the same, valid signature.
        assert_eq!(first, second);
        assert!(Bls::verify(key.public_key(), None, Root([42; 32]), &first));
        assert!(!Bls::verify(key.public_key(), None, Root([43; 32]), &first));
        assert_ne!(first, BlsSignature::default());
    }

    #[test]
    fn a_stateful_key_spends_a_fresh_leaf_per_signature() {
        // Fixture state: a toy key with 4 leaves and an empty ledger.
        let ledger = Arc::new(LeafLedger::in_memory());
        let key = LocalKey::<OneTimeToy>::with_ledger([5; 32], Arc::clone(&ledger));

        // Signing one root four times uses leaves 0 to 3: no leaf signs twice.
        let leaves: Vec<u64> = (0..4).map(|_| key.sign(Root([1; 32])).unwrap().1).collect();
        assert_eq!(leaves, [0, 1, 2, 3]);

        // The fifth signature finds every leaf spent.
        assert!(matches!(
            key.sign(Root([1; 32])),
            Err(LocalKeyError::Ledger(LedgerError::Exhausted { leaves: 4 }))
        ));
    }

    #[test]
    fn a_stateful_key_without_a_ledger_is_refused() {
        assert!(matches!(
            LocalKey::<OneTimeToy>::new([5; 32]),
            Err(LocalKeyError::LedgerRequired { scheme: "toy" })
        ));
    }
}
