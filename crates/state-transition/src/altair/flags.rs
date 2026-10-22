//! The participation flags a vote earns when a block includes it.

use axiom_types::{
    Preset,
    accessors::CoreState,
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
    phase0::AttestationData,
};

use crate::{BlockError, StateError};

/// A vote included in a block, with the state that judges it.
#[derive(Debug)]
pub struct Inclusion<'a, S: ?Sized> {
    /// The state at the including block.
    state: &'a S,
    /// The vote.
    data: &'a AttestationData,
    /// Slots between the vote and the including block.
    delay: u64,
}

impl<'a, S: CoreState + ?Sized> Inclusion<'a, S> {
    /// A vote included after some delay.
    #[must_use]
    pub const fn new(state: &'a S, data: &'a AttestationData, delay: u64) -> Self {
        Self { state, data, delay }
    }

    /// The participation flags the vote earns at its inclusion delay.
    ///
    /// ```text
    /// flag     requires                             inclusion delay
    /// source   source is the justified checkpoint   at most sqrt(slots per epoch)
    /// target   source and target match              within the deadline, if any
    /// head     source, target, and head match       exactly one slot
    /// ```
    ///
    /// Altair counts a target vote only within one epoch of delay.
    /// Deneb dropped that deadline, so late votes still count for the target, see EIP-7045.
    /// See `get_attestation_participation_flag_indices` in the Altair and Deneb specs.
    ///
    /// # Errors
    ///
    /// Fails when the source does not match, since such a vote cannot be included at all.
    pub fn flags(&self, target_deadline: Option<u64>) -> Result<Vec<usize>, BlockError> {
        let state = self.state;
        let data = self.data;
        let justified = if data.target.epoch == state.current_epoch() {
            state.current_justified_checkpoint()
        } else {
            state.previous_justified_checkpoint()
        };
        if data.source != justified {
            return Err(BlockError::AttestationSourceMismatch {
                claimed: data.source,
                justified,
            });
        }

        let target_root =
            state
                .block_root(data.target.epoch)
                .ok_or_else(|| StateError::BlockRootOutOfRange {
                    slot: data.target.epoch.start_slot::<S::Preset>(),
                    state_slot: state.slot(),
                })?;
        let head_root =
            state
                .block_root_at_slot(data.slot)
                .ok_or_else(|| StateError::BlockRootOutOfRange {
                    slot: data.slot,
                    state_slot: state.slot(),
                })?;
        let is_matching_target = data.target.root == target_root;
        let is_matching_head = is_matching_target && data.beacon_block_root == head_root;
        let target_in_time = target_deadline.is_none_or(|deadline| self.delay <= deadline);

        let mut flags = Vec::with_capacity(3);
        if self.delay <= S::Preset::SLOTS_PER_EPOCH.isqrt() {
            flags.push(TIMELY_SOURCE_FLAG_INDEX);
        }
        if is_matching_target && target_in_time {
            flags.push(TIMELY_TARGET_FLAG_INDEX);
        }
        if is_matching_head && self.delay == S::Preset::MIN_ATTESTATION_INCLUSION_DELAY {
            flags.push(TIMELY_HEAD_FLAG_INDEX);
        }
        Ok(flags)
    }
}
