//! One state, borrowed together with its caches.

use std::{collections::BTreeSet, sync::Arc};

use axiom_bls::PublicKey;
use axiom_types::{
    BlsPubkey, CommitteeIndex, Epoch, Gwei, Slot, ValidatorIndex, accessors::CoreState,
};

use crate::{BlockError, Caches, EpochCommittees, Fork, StateError, Verification};

/// A state of a known type, borrowed with the caches derived from it.
///
/// # Overview
///
/// Per-fork code gets the concrete state, so every field read is a plain field read.
/// The caches ride along, so keys and committees are computed once.
///
/// The type parameter is one fork's state for transition code.
/// It is the state of any fork for code that only needs the core.
#[derive(Debug)]
pub struct CachedState<'a, S: ?Sized> {
    /// The consensus state.
    pub(crate) beacon: &'a mut S,
    /// The caches derived from it.
    pub(crate) caches: &'a mut Caches,
}

impl<'a, S: CoreState + ?Sized> CachedState<'a, S> {
    /// A state and its caches.
    pub const fn new(beacon: &'a mut S, caches: &'a mut Caches) -> Self {
        Self { beacon, caches }
    }

    /// The same borrow, shortened, so the state can be lent to a step.
    pub const fn reborrow(&mut self) -> CachedState<'_, S> {
        CachedState {
            beacon: &mut *self.beacon,
            caches: &mut *self.caches,
        }
    }

    /// The consensus state.
    #[must_use]
    pub const fn beacon(&self) -> &S {
        self.beacon
    }

    /// The consensus state, for direct edits.
    ///
    /// Edits that reorder or replace validators invalidate the caches.
    /// Only spec tests need this, to set up a case.
    pub fn beacon_mut(&mut self) -> &mut S {
        // Direct edits may change active sets, so committees and proposers are recomputed on demand.
        self.caches.invalidate();
        self.beacon
    }

    /// Whether transitions check signatures.
    #[must_use]
    pub const fn verification(&self) -> Verification {
        self.caches.verification
    }

    /// Committees of the previous, current, or next epoch.
    ///
    /// # Errors
    ///
    /// Fails for any other epoch, whose committees are not fixed yet or no longer kept.
    pub fn committees(&mut self, epoch: Epoch) -> Result<Arc<EpochCommittees>, StateError> {
        self.caches.committees(&*self.beacon, epoch)
    }

    /// Committees of any epoch whose randomness the state holds, cached ones reused.
    ///
    /// Epochs outside the cached window are computed afresh and not kept.
    #[must_use]
    pub fn compute_committees(&mut self, epoch: Epoch) -> Arc<EpochCommittees> {
        self.committees(epoch)
            .unwrap_or_else(|_| Arc::new(EpochCommittees::compute(&*self.beacon, epoch)))
    }

    /// The beacon committee at a slot and index.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch is not cached or the committee does not exist.
    pub fn beacon_committee(
        &mut self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<Vec<ValidatorIndex>, BlockError> {
        let committees = self.committees(slot.epoch::<S::Preset>())?;
        committees
            .committee(slot, index)
            .map(<[ValidatorIndex]>::to_vec)
            .ok_or_else(|| BlockError::UnknownCommittee {
                slot,
                index,
                committees_per_slot: committees.committees_per_slot(),
            })
    }

    /// Validators that set their bit across some committees of a slot, sorted and unique.
    ///
    /// The bits run across the named committees, back to back.
    ///
    /// # Errors
    ///
    /// Fails when the epoch is not cached, a committee does not exist, or the bits run short.
    pub fn attesters(
        &mut self,
        slot: Slot,
        committee_indices: impl IntoIterator<Item = CommitteeIndex>,
        bits: impl ExactSizeIterator<Item = bool>,
    ) -> Result<BTreeSet<ValidatorIndex>, BlockError> {
        self.committees(slot.epoch::<S::Preset>())?
            .attesters(slot, committee_indices, bits)
    }

    /// Decompressed key of a validator.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or its key does not decompress.
    pub fn public_key(&mut self, index: ValidatorIndex) -> Result<PublicKey, StateError> {
        let validators = self.beacon.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        self.caches.pubkeys.sync(validators);
        self.caches
            .pubkeys
            .public_key(index, &validator.pubkey)
            .ok_or(StateError::MalformedPublicKey(index))
    }

    /// Index of the validator with a key.
    pub fn validator_index(&mut self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.caches.pubkeys.sync(self.beacon.validators());
        self.caches.pubkeys.index_of(pubkey)
    }

    /// Adds to a validator's balance.
    ///
    /// See `increase_balance` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or the balance overflows.
    pub fn increase_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), StateError> {
        let balance = self.balance_mut(index)?;
        *balance = balance.checked_add(delta).ok_or(StateError::Overflow {
            quantity: "balance",
        })?;
        Ok(())
    }

    /// Takes from a validator's balance, stopping at zero.
    ///
    /// See `decrease_balance` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist.
    pub fn decrease_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), StateError> {
        let balance = self.balance_mut(index)?;
        *balance = balance.saturating_sub(delta);
        Ok(())
    }

    /// A validator's balance, for an update.
    fn balance_mut(&mut self, index: ValidatorIndex) -> Result<&mut Gwei, StateError> {
        let balances = self.beacon.balances_mut();
        let registry_size = balances.len();
        balances
            .into_mut(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size,
            })
    }
}

impl<S: Fork> CachedState<'_, S> {
    /// Proposer of the state's slot, by the rules of the state's fork, drawn once per slot.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch has no active validator.
    pub fn proposer(&mut self) -> Result<ValidatorIndex, StateError> {
        let slot = self.beacon.slot();
        if let Some((fork, cached_slot, proposer)) = self.caches.proposer
            && fork == S::FORK
            && cached_slot == slot
        {
            return Ok(proposer);
        }
        let proposer = S::beacon_proposer_index(self.beacon)?;
        self.caches.proposer = Some((S::FORK, slot, proposer));
        Ok(proposer)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ForkName, Minimal, Slot, phase0};

    use super::*;

    #[test]
    fn the_proposer_is_drawn_once_per_slot_and_fork() {
        // Fixture state: an empty phase0 state at slot 5, whose draw would fail for lack of validators.
        let mut state = phase0::BeaconState::<Minimal> {
            slot: Slot(5),
            ..Default::default()
        };
        // A cached draw for slot 5 under phase0 is reused, so nothing is drawn.
        let mut caches = Caches {
            proposer: Some((ForkName::Phase0, Slot(5), ValidatorIndex(3))),
            ..Caches::default()
        };
        let mut cached = CachedState::new(&mut state, &mut caches);
        assert_eq!(cached.proposer(), Ok(ValidatorIndex(3)));

        // A direct edit drops the cached draw, so the empty registry now fails to draw.
        cached.beacon_mut();
        assert_eq!(
            cached.proposer(),
            Err(StateError::NoActiveValidators(Epoch(0)))
        );

        // A draw cached for another fork at the same slot is not reused either.
        caches.proposer = Some((ForkName::Altair, Slot(5), ValidatorIndex(3)));
        let mut cached = CachedState::new(&mut state, &mut caches);
        assert_eq!(
            cached.proposer(),
            Err(StateError::NoActiveValidators(Epoch(0)))
        );
    }
}
