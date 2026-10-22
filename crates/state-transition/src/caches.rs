//! Values derived from a state that every fork computes the same way.

use std::sync::Arc;

use axiom_types::{Epoch, accessors::CoreState};

use crate::{EpochCommittees, PubkeyCache, StateError, Verification};

/// Derived values that survive a fork upgrade, since no fork changed how they are computed.
///
/// # Invariants
///
/// The pubkey cache mirrors a prefix of the registry of the state it travels with.
/// Cached committees belong to epochs whose active set and seed are already fixed.
#[derive(Clone, Debug, Default)]
pub struct Caches {
    /// Decompressed keys and the key-to-index map.
    pub(crate) pubkeys: PubkeyCache,
    /// Committees of the previous, current, and next epochs, computed on demand.
    pub(crate) committees: Vec<Arc<EpochCommittees>>,
    /// Whether signatures are checked, including deposit proofs of possession.
    pub(crate) verification: Verification,
}

impl Caches {
    /// Caches for a state, reusing a pubkey cache built for an ancestor of it.
    #[must_use]
    pub fn new<S: CoreState + ?Sized>(state: &S, mut pubkeys: PubkeyCache) -> Self {
        pubkeys.sync(state.validators());
        Self {
            pubkeys,
            committees: Vec::new(),
            verification: Verification::Verify,
        }
    }

    /// Whether transitions check signatures.
    #[must_use]
    pub const fn verification(&self) -> Verification {
        self.verification
    }

    /// The pubkey cache, to seed the state of a descendant block.
    #[must_use]
    pub const fn pubkeys(&self) -> &PubkeyCache {
        &self.pubkeys
    }

    /// Committees of an epoch, from the cache or computed and kept.
    ///
    /// # Errors
    ///
    /// Fails for an epoch other than the previous, current, or next one of the state.
    pub fn committees<S: CoreState + ?Sized>(
        &mut self,
        state: &S,
        epoch: Epoch,
    ) -> Result<Arc<EpochCommittees>, StateError> {
        let current = state.current_epoch();
        if epoch < state.previous_epoch() || epoch > current + 1 {
            return Err(StateError::EpochOutOfRange { epoch, current });
        }
        if let Some(found) = self
            .committees
            .iter()
            .find(|cached| cached.epoch() == epoch)
        {
            return Ok(Arc::clone(found));
        }
        let computed = Arc::new(EpochCommittees::compute(state, epoch));
        self.committees.push(Arc::clone(&computed));
        Ok(computed)
    }

    /// Drops cached committees outside the previous, current, and next epochs.
    pub(crate) fn prune_committees(&mut self, current: Epoch) {
        self.committees.retain(|committees| {
            let epoch = committees.epoch();
            epoch.0 + 1 >= current.0 && epoch <= current + 1
        });
    }
}
