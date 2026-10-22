//! The secret keys the spec's test helpers give the validators of their genesis states.

use axiom_bls::SecretKey;
use axiom_types::{BlsSignature, Root, ValidatorIndex};

use crate::chain_builder::ChainBuilderError;

/// The pyspec test keys, one per validator index.
///
/// The secret key of validator i is the integer i + 1.
/// See `privkeys` in the pyspec test helpers, under `test/helpers/keys.py`.
#[derive(Debug)]
pub(crate) struct Keyring {
    /// The keys, indexed by validator.
    keys: Vec<SecretKey>,
}

impl Keyring {
    /// The keys of the first validators of a pyspec genesis.
    pub(crate) fn pyspec(count: usize) -> Self {
        let keys = (0..count)
            .map(|index| {
                let secret = index as u64 + 1;
                let mut bytes = [0; 32];
                bytes[24..].copy_from_slice(&secret.to_be_bytes());
                // Invariant: the scalar lies in 1..=2^64, nonzero and far below the group order.
                SecretKey::from_bytes(&bytes).expect("small nonzero scalars are valid keys")
            })
            .collect();
        Self { keys }
    }

    /// The compressed public key of a validator, if the keyring holds it.
    pub(crate) fn public_key(&self, index: usize) -> Option<[u8; 48]> {
        self.keys.get(index).map(|key| key.public_key().to_bytes())
    }

    /// A validator's signature over a signing root.
    ///
    /// # Errors
    ///
    /// Fails when the keyring holds no key for the validator.
    pub(crate) fn sign(
        &self,
        index: ValidatorIndex,
        signing_root: Root,
    ) -> Result<BlsSignature, ChainBuilderError> {
        let key = self
            .keys
            .get(index.as_usize())
            .ok_or(ChainBuilderError::NoKey {
                index,
                keys: self.keys.len(),
            })?;
        Ok(BlsSignature(key.sign(&signing_root.0).to_bytes()))
    }

    /// The aggregate signature of several validators over one signing root.
    ///
    /// A member listed twice signs twice, as a sync committee seat held twice does.
    ///
    /// # Algorithm
    ///
    /// Signing is linear in the secret key, so the aggregate is one signature:
    ///
    /// ```text
    /// sum_i (sk_i * H(m)) = (sum_i sk_i) * H(m)
    /// ```
    ///
    /// With secret i + 1 for validator i, the summed secret is a small integer.
    /// See `Aggregate` in the BLS signature draft, section 2.8.
    ///
    /// # Errors
    ///
    /// Fails when a member has no key, or when no member signs.
    pub(crate) fn sign_together(
        &self,
        members: &[ValidatorIndex],
        signing_root: Root,
    ) -> Result<BlsSignature, ChainBuilderError> {
        let mut secret: u64 = 0;
        for &index in members {
            if index.as_usize() >= self.keys.len() {
                return Err(ChainBuilderError::NoKey {
                    index,
                    keys: self.keys.len(),
                });
            }
            // Invariant: at most 2^20 members with secrets below 2^20 sum far below 2^64.
            secret += index.0 + 1;
        }
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&secret.to_be_bytes());
        let key = SecretKey::from_bytes(&bytes).map_err(|_| ChainBuilderError::NoSigners)?;
        Ok(BlsSignature(key.sign(&signing_root.0).to_bytes()))
    }
}
