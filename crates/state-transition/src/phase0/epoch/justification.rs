//! Casper FFG justification and finalization.

use axiom_types::{Epoch, Gwei, accessors::CoreState, phase0::Checkpoint};

use crate::StateError;

/// The target votes of the two epochs the state tracks, weighed against the total stake.
///
/// Phase0 tallies the votes from pending attestations, Altair from participation flags.
/// The weighing itself never changed.
/// See `weigh_justification_and_finalization` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Justification {
    /// The epoch that is ending.
    pub(crate) current_epoch: Epoch,
    /// The epoch before it.
    pub(crate) previous_epoch: Epoch,
    /// Total active balance.
    pub(crate) total: Gwei,
    /// Target votes for the previous epoch.
    pub(crate) previous_target: Gwei,
    /// Target votes for the current epoch.
    pub(crate) current_target: Gwei,
}

impl Justification {
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
    pub fn weigh<S: CoreState + ?Sized>(self, state: &mut S) -> Result<(), StateError> {
        // The first two epochs keep their genesis checkpoints, whose roots are stubs.
        if self.current_epoch.0 <= Epoch::GENESIS.0 + 1 {
            return Ok(());
        }
        let total = self.total;
        let old_previous_justified = state.previous_justified_checkpoint();
        let old_current_justified = state.current_justified_checkpoint();
        // Shift the history one epoch older.
        *state.previous_justified_checkpoint_mut() = old_current_justified;
        let mut bits = [false; 4];
        for (index, bit) in bits.iter_mut().enumerate().skip(1) {
            *bit = state.justification_bits().get(index - 1).unwrap_or(false);
        }
        // Threshold: target balance * 3 >= total * 2, a two-thirds supermajority.
        for (epoch, balance, bit) in [
            (self.previous_epoch, self.previous_target, 1),
            (self.current_epoch, self.current_target, 0),
        ] {
            if u128::from(balance.0) * 3 >= u128::from(total.0) * 2 {
                let root =
                    state
                        .block_root(epoch)
                        .ok_or_else(|| StateError::BlockRootOutOfRange {
                            slot: epoch.start_slot::<S::Preset>(),
                            state_slot: state.slot(),
                        })?;
                *state.current_justified_checkpoint_mut() = Checkpoint { epoch, root };
                bits[bit] = true;
            }
        }
        for (index, bit) in bits.iter().enumerate() {
            state.justification_bits_mut().set(index, *bit);
        }
        let current = self.current_epoch;
        let finalized = state.finalized_checkpoint_mut();
        if bits[1..4].iter().all(|bit| *bit) && old_previous_justified.epoch + 3 == current {
            *finalized = old_previous_justified;
        }
        if bits[1..3].iter().all(|bit| *bit) && old_previous_justified.epoch + 2 == current {
            *finalized = old_previous_justified;
        }
        if bits[0..3].iter().all(|bit| *bit) && old_current_justified.epoch + 2 == current {
            *finalized = old_current_justified;
        }
        if bits[0..2].iter().all(|bit| *bit) && old_current_justified.epoch + 1 == current {
            *finalized = old_current_justified;
        }
        Ok(())
    }
}
