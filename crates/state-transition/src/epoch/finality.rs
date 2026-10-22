//! Casper FFG justification and finalization, and the inactivity scores that back it.

use axiom_types::{Checkpoint, Epoch, Preset, constants::TIMELY_TARGET_FLAG_INDEX};

use super::EpochProcessor;
use crate::StateError;

impl<P: Preset> EpochProcessor<'_, P> {
    /// Justifies epochs with two thirds of target votes, and finalizes along justified chains.
    ///
    /// # Algorithm
    ///
    /// Justification: an epoch whose target votes carry two thirds of the stake is justified.
    ///
    /// Finalization: a justified checkpoint is finalized when it is the source of a
    /// supermajority link to its direct child, or to a grandchild through a justified middle.
    ///
    /// ```text
    /// bits (newest first)   source                  finalized when
    /// 1 . 1 1 . .           justified 3 epochs ago   bits 1..4 set, source 3 back
    /// . 1 1 . . .           justified 2 epochs ago   bits 1..3 set, source 2 back
    /// 1 1 1 . . .           current justified        bits 0..3 set, source 2 back
    /// 1 1 . . . .           current justified        bits 0..2 set, source 1 back
    /// ```
    ///
    /// Two conflicting finalized checkpoints imply that a third of the stake is slashable.
    /// See the Gasper paper, sections 3 and 4, and `weigh_justification_and_finalization`.
    ///
    /// # Errors
    ///
    /// Fails when a justified epoch's block root is no longer in the state.
    pub fn process_justification_and_finalization(&mut self) -> Result<(), StateError> {
        // The first two epochs keep their genesis checkpoints, whose roots are stubs.
        if self.current_epoch.0 <= Epoch::GENESIS.0 + 1 {
            return Ok(());
        }
        let total = self.total_active_balance;
        let previous_target =
            self.unslashed_participating_balance(TIMELY_TARGET_FLAG_INDEX, self.previous_epoch);
        let current_target =
            self.unslashed_participating_balance(TIMELY_TARGET_FLAG_INDEX, self.current_epoch);

        let state = &mut self.state.beacon;
        let old_previous_justified = state.previous_justified_checkpoint;
        let old_current_justified = state.current_justified_checkpoint;

        // Shift the history one epoch older.
        state.previous_justified_checkpoint = state.current_justified_checkpoint;
        let mut bits = [false; 4];
        for (index, bit) in bits.iter_mut().enumerate().skip(1) {
            *bit = state.justification_bits.get(index - 1).unwrap_or(false);
        }

        // Threshold: target balance * 3 >= total * 2, a two-thirds supermajority.
        for (epoch, balance, bit) in [
            (self.previous_epoch, previous_target, 1),
            (self.current_epoch, current_target, 0),
        ] {
            if u128::from(balance.0) * 3 >= u128::from(total.0) * 2 {
                let root =
                    state
                        .block_root(epoch)
                        .ok_or_else(|| StateError::BlockRootOutOfRange {
                            slot: epoch.start_slot::<P>(),
                            state_slot: state.slot,
                        })?;
                state.current_justified_checkpoint = Checkpoint { epoch, root };
                bits[bit] = true;
            }
        }
        for (index, bit) in bits.iter().enumerate() {
            state.justification_bits.set(index, *bit);
        }

        let current = self.current_epoch;
        if bits[1..4].iter().all(|bit| *bit) && old_previous_justified.epoch + 3 == current {
            state.finalized_checkpoint = old_previous_justified;
        }
        if bits[1..3].iter().all(|bit| *bit) && old_previous_justified.epoch + 2 == current {
            state.finalized_checkpoint = old_previous_justified;
        }
        if bits[0..3].iter().all(|bit| *bit) && old_current_justified.epoch + 2 == current {
            state.finalized_checkpoint = old_current_justified;
        }
        if bits[0..2].iter().all(|bit| *bit) && old_current_justified.epoch + 1 == current {
            state.finalized_checkpoint = old_current_justified;
        }
        Ok(())
    }

    /// Updates inactivity scores from the previous epoch's target votes.
    ///
    /// A missed target adds the bias, a hit removes one point.
    /// Outside a leak every score also decays by the recovery rate.
    ///
    /// See `process_inactivity_updates` in the Altair beacon chain spec.
    pub fn process_inactivity_updates(&mut self) {
        if self.current_epoch == Epoch::GENESIS {
            return;
        }
        let in_leak = self.state.beacon.is_in_inactivity_leak();
        let bias = self.config.inactivity_score_bias;
        let recovery = self.config.inactivity_score_recovery_rate;
        for index in self.state.beacon.eligible_validator_indices() {
            let index = index.as_usize();
            let participated = self.is_previous_participant(index, TIMELY_TARGET_FLAG_INDEX);
            let score = &mut self.state.beacon.inactivity_scores[index];
            *score = if participated {
                score.saturating_sub(1)
            } else {
                score.saturating_add(bias)
            };
            if !in_leak {
                *score = score.saturating_sub(recovery);
            }
        }
    }
}
