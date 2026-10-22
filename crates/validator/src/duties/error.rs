//! Why a duty could not be performed.

use axiom_types::{Slot, ValidatorIndex};
use thiserror::Error;

use crate::{beacon::BeaconError, signing::SignError};

/// A duty that failed.
#[derive(Debug, Error)]
pub enum DutyError {
    /// No beacon node served the request.
    #[error("beacon node: {0}")]
    Beacon(#[from] BeaconError),
    /// The validator could not sign.
    #[error("signing: {0}")]
    Sign(#[from] SignError),
    /// A produced block is not for the slot or proposer asked for.
    ///
    /// A beacon node is not trusted to produce what was asked; this guards against a buggy or hostile one.
    #[error(
        "produced block is for slot {slot} by {proposer}, asked slot {expected_slot} by {expected_proposer}"
    )]
    WrongBlock {
        /// Slot of the produced block.
        slot: Slot,
        /// Proposer of the produced block.
        proposer: ValidatorIndex,
        /// The slot asked for.
        expected_slot: Slot,
        /// The proposer asked for.
        expected_proposer: ValidatorIndex,
    },
    /// Votes or data from a node are for another slot than asked.
    #[error("beacon node answered for slot {slot}, asked {expected}")]
    WrongSlot {
        /// The slot answered.
        slot: Slot,
        /// The slot asked for.
        expected: Slot,
    },
}
