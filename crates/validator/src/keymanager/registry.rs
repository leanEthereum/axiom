//! The keys the client runs and the directory that keeps them, edited one request at a time.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axiom_types::BlsPubkey;

use crate::{
    keymanager::{DirectoryError, KeyDirectory},
    signing::{SignError, ValidatorSigner},
    validators::{ValidatorSettings, ValidatorStore},
};

/// The running keys and their durable copy, which key requests edit together.
#[derive(Debug)]
pub(crate) struct KeyRegistry {
    /// The keys that sign.
    store: Arc<ValidatorStore>,
    /// Where keys persist across restarts.
    directory: Arc<KeyDirectory>,
    /// Whether a new key may sign at once; doppelganger detection holds it back instead.
    signs_at_once: bool,
    /// Serializes edits, so two requests never both see a key as absent and both add it.
    edits: Mutex<()>,
}

impl KeyRegistry {
    /// A registry over a store and a directory.
    pub(crate) const fn new(
        store: Arc<ValidatorStore>,
        directory: Arc<KeyDirectory>,
        signs_at_once: bool,
    ) -> Self {
        Self {
            store,
            directory,
            signs_at_once,
            edits: Mutex::new(()),
        }
    }

    /// The keys that sign.
    pub(crate) fn store(&self) -> &ValidatorStore {
        &self.store
    }

    /// Where keys persist.
    pub(crate) fn directory(&self) -> &KeyDirectory {
        &self.directory
    }

    /// Holds off every other edit until the guard drops.
    pub(crate) fn edit(&self) -> MutexGuard<'_, ()> {
        // The lock guards no data, so a poisoned one is as good as a clean one.
        self.edits.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts running a key, enabled unless doppelganger detection must clear it first.
    ///
    /// # Errors
    ///
    /// Fails when slashing protection cannot record the key.
    pub(crate) fn run(&self, signer: ValidatorSigner) -> Result<BlsPubkey, SignError> {
        self.store.add(signer, self.signs_at_once)
    }

    /// The signer of a key the store runs.
    pub(crate) fn signer(&self, pubkey: &BlsPubkey) -> Option<Arc<ValidatorSigner>> {
        self.store.signer(pubkey)
    }

    /// Changes a running key's overrides, on disk first and then in the store.
    ///
    /// A key the directory does not define, such as one given on the command line, changes in memory only.
    ///
    /// # Returns
    ///
    /// Whether the store runs the key.
    ///
    /// # Errors
    ///
    /// Fails when the definitions cannot be written; the store then keeps its old overrides.
    pub(crate) fn edit_settings(
        &self,
        pubkey: &BlsPubkey,
        change: impl Fn(&mut ValidatorSettings),
    ) -> Result<bool, DirectoryError> {
        let _edit = self.edit();
        if !self.store.contains(pubkey) {
            return Ok(false);
        }
        self.directory.edit_settings(pubkey, &change)?;
        Ok(self.store.edit_overrides(pubkey, change))
    }
}
