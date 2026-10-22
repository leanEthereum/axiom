//! Committees of recent vote targets, each computed once, to name a vote's signers.

use std::sync::Arc;

use axiom_fork_choice::Store;
use axiom_state_transition::EpochCommittees;
use axiom_types::{
    Preset, ValidatorIndex, accessors::CoreState, phase0::Checkpoint, vote::CommitteeVote,
};

/// Target checkpoints whose committees are kept: two epochs, two branches each.
const CACHED_TARGETS: usize = 4;

/// The committees of the last few target checkpoints votes named.
///
/// Shuffling walks every validator, so each target's committees are computed once.
/// A vote's signers come from its target checkpoint's committees, as the spec computes them.
/// See `get_attesting_indices` and `store_target_checkpoint_state` in the phase0 specs.
#[derive(Clone, Debug, Default)]
pub(crate) struct TargetCommittees {
    /// Committees by target checkpoint, the most recent last.
    cached: Vec<(Checkpoint, Arc<EpochCommittees>)>,
}

impl TargetCommittees {
    /// The committees of a target checkpoint, from the cache or the target block's state.
    ///
    /// A target block more than an epoch old is advanced to the target's epoch first.
    /// Its active set and seed then match the checkpoint state's, see the phase0 fork choice spec.
    pub(crate) fn of<P: Preset>(
        &mut self,
        store: &Store<P>,
        target: Checkpoint,
    ) -> Option<Arc<EpochCommittees>> {
        if let Some((_, committees)) = self.cached.iter().find(|(seen, _)| *seen == target) {
            return Some(Arc::clone(committees));
        }
        let state = store.block_state(&target.root)?;
        let computed = if state.beacon().current_epoch() + 1 < target.epoch {
            let mut advanced = state.clone();
            advanced
                .process_slots(store.config(), target.epoch.start_slot::<P>())
                .ok()?;
            EpochCommittees::compute(advanced.beacon(), target.epoch)
        } else {
            EpochCommittees::compute(state.beacon(), target.epoch)
        };
        let computed = Arc::new(computed);
        if self.cached.len() == CACHED_TARGETS {
            self.cached.remove(0);
        }
        self.cached.push((target, Arc::clone(&computed)));
        Some(computed)
    }

    /// The validators whose bits a vote sets, or nothing when its target or committees are unknown.
    pub(crate) fn signers<P: Preset>(
        &mut self,
        store: &Store<P>,
        vote: &CommitteeVote,
    ) -> Option<Vec<ValidatorIndex>> {
        let data = &vote.data;
        self.of(store, data.target)?
            .attesters(
                data.slot,
                vote.committees.iter().copied(),
                vote.bits.iter().copied(),
            )
            .ok()
            .map(|signers| signers.into_iter().collect())
    }
}
