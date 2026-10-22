//! Rewards, split by what earned them, as the beacon node API reports them.
//!
//! # Overview
//!
//! The state transition pays rewards as plain balance changes.
//! Explaining a balance change needs the same computation, kept apart by source:
//!
//! - an epoch's attestation rewards, per validator and per vote component,
//! - a block's payments to its proposer, per operation type,
//! - a block's sync committee rewards and penalties, per committee member.
//!
//! Each reuses the spec functions the transition runs, so the numbers are the paid ones.
//! See the rewards routes of the beacon node API.

mod attester;
mod block;
mod ledger;
mod sync_committee;

use std::fmt;

pub use attester::{AttesterReward, AttesterRewards, IdealAttesterReward};
use axiom_types::{Epoch, ForkName, Gwei, Slot};
pub use block::BlockRewards;
pub(crate) use ledger::ProposerLedger;
pub use sync_committee::SyncCommitteeReward;
use thiserror::Error;

use crate::{StateError, TransitionError};

/// An amount of gwei that may be negative: a reward net of a penalty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignedGwei(pub i64);

impl SignedGwei {
    /// A reward less a penalty, saturating at the bounds of 64 signed bits.
    #[must_use]
    pub fn net(reward: Gwei, penalty: Gwei) -> Self {
        let difference = i128::from(reward.0) - i128::from(penalty.0);
        Self(i64::try_from(difference).unwrap_or(if difference < 0 { i64::MIN } else { i64::MAX }))
    }
}

impl From<Gwei> for SignedGwei {
    fn from(reward: Gwei) -> Self {
        Self::net(reward, Gwei::ZERO)
    }
}

impl fmt::Display for SignedGwei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Why rewards cannot be computed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RewardsError {
    /// The state is past the slot whose transition pays the epoch's votes.
    #[error("state at slot {slot} is past slot {last}, which pays the votes of epoch {epoch}")]
    StatePastEpoch {
        /// The epoch asked for.
        epoch: Epoch,
        /// The state's slot.
        slot: Slot,
        /// The last slot before the paying transition.
        last: Slot,
    },
    /// The block's fork has no sync committee, which Altair introduced.
    #[error("a {0} block has no sync committee")]
    NoSyncCommittee(ForkName),
    /// The state broke an invariant.
    #[error(transparent)]
    State(#[from] StateError),
    /// The block does not apply to the state.
    #[error(transparent)]
    Transition(#[from] TransitionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_amounts_carry_their_sign_and_saturate() {
        // 7 earned and 3 charged nets 4; the reverse nets -4.
        assert_eq!(SignedGwei::net(Gwei(7), Gwei(3)), SignedGwei(4));
        assert_eq!(SignedGwei::net(Gwei(3), Gwei(7)), SignedGwei(-4));

        // Amounts past 2^63 clamp to the signed range instead of wrapping.
        assert_eq!(
            SignedGwei::net(Gwei(u64::MAX), Gwei(0)),
            SignedGwei(i64::MAX)
        );
        assert_eq!(
            SignedGwei::net(Gwei(0), Gwei(u64::MAX)),
            SignedGwei(i64::MIN)
        );
    }
}
