//! The current epoch's target on the head's chain, and whether it will be justified.

use axiom_state_transition::State;
use axiom_types::{
    Gwei, Preset, Root, ValidatorIndex, accessors::CoreState, combined::BeaconState,
    fulu::Checkpoint,
};

use super::{safety::Safety, slot_range::SlotRange};
use crate::{ForkChoiceError, Store};

/// The current epoch's checkpoint on the head's chain, as the store sees it.
#[derive(Clone, Copy, Debug)]
pub(super) struct CurrentTarget<'a, P: Preset> {
    /// The store.
    store: &'a Store<P>,
    /// The head whose chain holds the target.
    head: Root,
    /// The target checkpoint.
    target: Checkpoint,
}

impl<'a, P: Preset> CurrentTarget<'a, P> {
    /// The target on a head's chain.
    ///
    /// # Errors
    ///
    /// Fails when the head is not in the store.
    pub(super) fn of(store: &'a Store<P>, head: Root) -> Result<Self, ForkChoiceError> {
        let epoch = store.current_epoch();
        let root = store
            .checkpoint_block(head, epoch)
            .ok_or(ForkChoiceError::MissingState(head))?;
        Ok(Self {
            store,
            head,
            target: Checkpoint { epoch, root },
        })
    }

    /// Whether honest votes alone keep any conflicting checkpoint from justification.
    ///
    /// See `will_no_conflicting_checkpoint_be_justified` in the phase0 fast confirmation spec.
    pub(super) fn blocks_conflicting_justification(&self) -> Result<bool, ForkChoiceError> {
        if self.target == self.store.checkpoints.unrealized_justified() {
            return Ok(true);
        }
        let state = self.pulled_up_head_state()?;
        let total = state.beacon().total_active_balance();
        let honest = self.honest_support(state.beacon())?;
        // Threshold: more than a third of honest support blocks any other justification.
        Ok(u128::from(honest.0) * 3 > u128::from(total.0))
    }

    /// Whether honest votes alone will justify the target.
    ///
    /// See `will_current_target_be_justified` in the phase0 fast confirmation spec.
    pub(super) fn will_be_justified(&self) -> Result<bool, ForkChoiceError> {
        let state = self.pulled_up_head_state()?;
        let total = state.beacon().total_active_balance();
        let honest = self.honest_support(state.beacon())?;
        // Threshold: two thirds of the stake.
        Ok(u128::from(honest.0) * 3 >= u128::from(total.0) * 2)
    }

    /// Lower bound on the honest FFG support the target will collect this epoch.
    ///
    /// Support seen so far, less the adversary's share, plus the honest share of slots to come.
    /// See `compute_honest_ffg_support_for_current_target` in the phase0 fast confirmation spec.
    fn honest_support(&self, state: &BeaconState<P>) -> Result<Gwei, ForkChoiceError> {
        let store = self.store;
        let current_slot = store.current_slot();
        let elapsed = SlotRange::new(
            current_slot.epoch::<P>().start_slot::<P>(),
            current_slot.saturating_sub(1),
        );
        let total = state.total_active_balance();

        let support = self.score(state);
        let remaining = total.saturating_sub(elapsed.committee_weight::<P>(total));
        let remaining_honest =
            remaining / 100 * (100 - store.config.confirmation_byzantine_threshold);
        let adversarial = Safety::new(store, state, self.head).adversarial_weight_in(elapsed)?;
        Ok(support.saturating_sub(adversarial) + remaining_honest)
    }

    /// FFG support of the target, estimated from LMD-GHOST votes.
    ///
    /// See `get_current_target_score` in the phase0 fast confirmation spec.
    fn score(&self, state: &BeaconState<P>) -> Gwei {
        let target = self.target;
        let epoch = state.current_epoch();
        let mut score = Gwei::ZERO;
        for (index, validator) in state.validators().iter().enumerate() {
            if !validator.is_active_at(epoch) || validator.slashed {
                continue;
            }
            if let Some(message) = self.store.votes.counted(ValidatorIndex::from(index))
                && self.store.checkpoint_block(message.root, message.epoch) == Some(target.root)
                && message.epoch == target.epoch
            {
                score += validator.effective_balance;
            }
        }
        score
    }

    /// The head's state, advanced to the current epoch when it lags behind.
    ///
    /// See `get_pulled_up_head_state` in the phase0 fast confirmation spec.
    fn pulled_up_head_state(&self) -> Result<State<P>, ForkChoiceError> {
        let store = self.store;
        let mut state = store
            .block_states
            .get(&self.head)
            .cloned()
            .ok_or(ForkChoiceError::MissingState(self.head))?;
        let epoch = store.current_epoch();
        if state.beacon().current_epoch() < epoch {
            state.process_slots(&store.config, epoch.start_slot::<P>())?;
        }
        Ok(state)
    }
}
