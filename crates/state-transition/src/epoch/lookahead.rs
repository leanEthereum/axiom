//! Rotations that look ahead: sync committees and the proposer lookahead.

use std::mem;

use axiom_bls::PublicKey;
use axiom_types::{BeaconState, BlsPubkey, Epoch, Preset, SyncCommittee, ValidatorIndex};

use crate::{State, StateError, sampling::WeightedSampler};

/// The duties an epoch transition fixes in advance, seen from the ending epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Lookahead {
    /// The epoch that is ending.
    current: Epoch,
}

impl Lookahead {
    /// The lookahead from an ending epoch.
    pub(super) const fn new(current: Epoch) -> Self {
        Self { current }
    }

    /// Rotates the sync committees when a period ends.
    ///
    /// The next committee is drawn a full period ahead.
    /// A light client can then learn it from the current committee's signatures.
    ///
    /// See `process_sync_committee_updates` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the next committee cannot be drawn.
    pub(super) fn rotate_sync_committees<P: Preset>(
        self,
        state: &mut State<P>,
    ) -> Result<(), StateError> {
        if (self.current + 1)
            .0
            .is_multiple_of(P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
        {
            let next = Self::next_sync_committee(state)?;
            let beacon = &mut state.beacon;
            beacon.current_sync_committee = mem::replace(&mut beacon.next_sync_committee, next);
        }
        Ok(())
    }

    /// Drops the ending epoch's proposers, and appends those of the epoch after the next.
    ///
    /// ```text
    /// lookahead before: [ epoch e   | epoch e+1 ]
    /// lookahead after:  [ epoch e+1 | epoch e+2 ]
    /// ```
    ///
    /// Fixing proposers an epoch early lets them prepare, and keeps the schedule stable.
    /// See EIP-7917 and `process_proposer_lookahead` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the new epoch has no active validator.
    pub(super) fn shift_proposers<P: Preset>(
        self,
        state: &mut BeaconState<P>,
    ) -> Result<(), StateError> {
        let epoch = self.current + P::MIN_SEED_LOOKAHEAD + 1;
        let proposers: Vec<ValidatorIndex> = WeightedSampler::proposers(state, epoch)?;
        let lookahead = &mut state.proposer_lookahead;
        let slots = P::SLOTS_PER_EPOCH as usize;
        lookahead.rotate_left(slots);
        let tail = lookahead.len() - slots;
        lookahead[tail..].copy_from_slice(&proposers);
        Ok(())
    }

    /// The next sync committee, with its aggregate key.
    ///
    /// See `get_next_sync_committee` in the Altair beacon chain spec.
    fn next_sync_committee<P: Preset>(
        state: &mut State<P>,
    ) -> Result<SyncCommittee<P>, StateError> {
        let indices = WeightedSampler::next_sync_committee(&state.beacon)?;
        let pubkeys: Vec<BlsPubkey> = indices
            .iter()
            .map(|index| state.beacon.validators[index.as_usize()].pubkey)
            .collect();

        let keys = indices
            .iter()
            .map(|index| state.public_key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        let aggregate = PublicKey::aggregate(&keys).map_err(StateError::InvalidSyncCommittee)?;

        Ok(SyncCommittee {
            pubkeys: pubkeys
                .try_into()
                .map_err(|source| StateError::Capacity {
                    list: "next sync committee",
                    source,
                })?,
            aggregate_pubkey: BlsPubkey(aggregate.to_bytes()),
        })
    }
}
