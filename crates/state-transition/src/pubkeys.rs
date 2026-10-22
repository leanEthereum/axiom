//! Decompressed validator keys and the reverse index from key to validator.

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use axiom_bls::PublicKey;
use axiom_types::{BlsPubkey, ValidatorIndex, phase0::Validator};

/// Decompressed public keys and a key-to-index map, grown with the registry.
///
/// # Overview
///
/// Decompressing a key costs a square root and a subgroup check, about 50 microseconds.
/// A block can carry thousands of signers, so each key is decompressed at most once.
///
/// # Invariants
///
/// Entries mirror a prefix of one registry, in order.
/// The registry only ever appends, so a prefix stays valid as the chain grows.
///
/// Clones share storage until one of them appends.
/// Two forks that append different validators then hold separate copies.
#[derive(Clone, Debug, Default)]
pub struct PubkeyCache {
    /// Decompressed key per validator, filled on first use.
    keys: Arc<Vec<OnceLock<Option<PublicKey>>>>,
    /// Validator index of each key bytes.
    indices: Arc<HashMap<BlsPubkey, ValidatorIndex>>,
}

impl PubkeyCache {
    /// Number of validators the cache mirrors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the cache mirrors no validator.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Extends the cache to mirror every validator of a registry.
    pub fn sync(&mut self, validators: &[Validator]) {
        if validators.len() <= self.keys.len() {
            return;
        }
        let start = self.keys.len();
        let keys = Arc::make_mut(&mut self.keys);
        let indices = Arc::make_mut(&mut self.indices);
        for (offset, validator) in validators[start..].iter().enumerate() {
            keys.push(OnceLock::new());
            // The first validator with a key wins, as the spec's list lookup does.
            indices
                .entry(validator.pubkey)
                .or_insert_with(|| ValidatorIndex::from(start + offset));
        }
    }

    /// Index of the validator with a key, among the mirrored validators.
    #[must_use]
    pub fn index_of(&self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.indices.get(pubkey).copied()
    }

    /// Decompressed key of a mirrored validator, or nothing when its bytes are not a valid key.
    ///
    /// # Panics
    ///
    /// Panics when the index is not mirrored, which means the cache was not synced.
    #[must_use]
    pub fn public_key(&self, index: ValidatorIndex, bytes: &BlsPubkey) -> Option<PublicKey> {
        self.keys[index.as_usize()]
            .get_or_init(|| PublicKey::from_bytes(&bytes.0).ok())
            .clone()
    }
}
