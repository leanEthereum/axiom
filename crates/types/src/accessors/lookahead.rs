//! The proposer lookahead, from Fulu on.

use crate::{ValidatorIndex, accessors::CoreState, fulu::ProposerLookahead};

/// Proposers fixed one epoch ahead, see EIP-7917.
///
/// See the Fulu beacon chain spec.
pub trait LookaheadState: CoreState {
    /// Proposers of the current and next epochs, by slot.
    fn proposer_lookahead(&self) -> &ProposerLookahead<Self::Preset>;

    /// Proposers of the current and next epochs, for the epoch shift.
    fn proposer_lookahead_mut(&mut self) -> &mut ProposerLookahead<Self::Preset>;

    /// Proposer of the state's slot, read from the lookahead.
    ///
    /// See `get_beacon_proposer_index` in the Fulu beacon chain spec.
    fn lookahead_proposer(&self) -> ValidatorIndex {
        self.proposer_lookahead()[self.slot().index_in_epoch::<Self::Preset>() as usize]
    }
}
