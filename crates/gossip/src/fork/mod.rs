//! What each fork's p2p spec changes in the gossip rules, implemented on that fork's state.
//!
//! # Overview
//!
//! The rules of the phase0 topics survive every fork, with a few amendments.
//! Bellatrix checks the payload, Deneb widens the vote window, Electra moves the committee index.
//! Each fork's file implements the trait below once, and reads as the fork's list of amendments.
//!
//! Dispatch happens once, when the caller names the fork of the topic.
//! The rules below that point run on that fork's concrete types.

mod altair;
mod bellatrix;
mod capella;
mod deneb;
mod electra;
mod fulu;
mod gloas;
mod hstar;
mod phase0;

use axiom_ssz::Ssz;
use axiom_state_transition::{Fork, SignedBlock, State};
use axiom_types::{
    BlsSignature, ChainConfig, CommitteeIndex, Domain, Epoch, Hash32, accessors::CoreState,
    combined, constants::DOMAIN_VOLUNTARY_EXIT, gloas::ExecutionPayloadBid, vote::PayloadClaim,
};

pub(crate) use self::gloas::{Bounded, BuilderFunds, ExecutionRequestLimits, GasTarget, Ptc};
use crate::{
    ChainView, GossipError,
    vote::{SignedAggregate, SlashingEvidence, SubnetVote},
};

/// Shorthand for a rule's outcome.
pub(crate) type Verdict = Result<(), GossipError>;

/// How long after its slot a vote may still propagate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteWindow {
    /// A fixed number of slots after the vote's slot.
    ///
    /// See `ATTESTATION_PROPAGATION_SLOT_RANGE` in the phase0 p2p spec.
    SlotRange,
    /// Any time in the vote's epoch or the next, so late votes still count.
    ///
    /// See EIP-7045, adopted by the Deneb p2p spec.
    CurrentOrPreviousEpoch,
}

/// What the index field of a vote's data means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteIndex {
    /// The committee the vote comes from.
    Committee,
    /// Nothing, so it must be zero: the committee is named outside the data.
    ///
    /// See EIP-7549, adopted by the Electra p2p spec.
    Zero,
    /// Whether the voter saw the slot's execution payload, zero or one.
    ///
    /// See EIP-7732, adopted by the Gloas p2p spec.
    PayloadPresence,
}

impl VoteIndex {
    /// What a vote with this data index says about its head's payload.
    #[must_use]
    pub const fn payload_claim(self, index: CommitteeIndex) -> PayloadClaim {
        match self {
            Self::PayloadPresence => PayloadClaim::of_index(index),
            Self::Committee | Self::Zero => PayloadClaim::Silent,
        }
    }

    /// The violated rule, when an aggregate's data index breaks this meaning.
    #[must_use]
    pub const fn aggregate_violation(self, index: u64) -> Option<&'static str> {
        match self {
            Self::Zero if index != 0 => Some("aggregate data index is non-zero"),
            Self::PayloadPresence if index > 1 => Some("aggregate data index must be 0 or 1"),
            Self::Committee | Self::Zero | Self::PayloadPresence => None,
        }
    }

    /// The violated rule, when a subnet attestation's data index breaks this meaning.
    #[must_use]
    pub const fn attestation_violation(self, index: u64) -> Option<&'static str> {
        match self {
            Self::Zero if index != 0 => Some("attestation data index is non-zero"),
            Self::PayloadPresence if index > 1 => Some("attestation data index must be 0 or 1"),
            Self::Committee | Self::Zero | Self::PayloadPresence => None,
        }
    }
}

/// The gossip rules of one fork, implemented on that fork's state.
///
/// # Overview
///
/// The associated types are the fork's messages on the topics every fork shares.
/// The constants and methods are the amendments later forks made to the phase0 rules.
/// A method's default is the phase0 rule, which a fork overrides only where its spec did.
///
/// A trait exists here because eight forks differ in their containers and amendments.
pub trait GossipFork: Fork {
    /// The fork's signed block.
    type SignedBeaconBlock: SignedBlock<Self::Preset> + Ssz;

    /// The fork's message on the aggregate topic.
    type SignedAggregateAndProof: SignedAggregate + Ssz;

    /// The fork's message on the attestation subnets.
    type SubnetAttestation: SubnetVote + Ssz;

    /// The fork's attester slashing.
    type AttesterSlashing: SlashingEvidence + Ssz;

    /// How long votes propagate.
    const VOTE_WINDOW: VoteWindow;

    /// What a vote's data index means.
    const VOTE_INDEX: VoteIndex;

    /// The signed block as a block of any fork.
    fn into_any_block(signed: Self::SignedBeaconBlock)
    -> combined::SignedBeaconBlock<Self::Preset>;

    /// The unsigned block and the proposer's signature.
    fn split_block(signed: &Self::SignedBeaconBlock) -> (&Self::Block, &BlsSignature);

    /// Hash of the execution block a beacon block commits to, zero before the merge.
    fn execution_block_hash(block: &Self::Block) -> Hash32;

    /// The builder's bid a block carries, from Gloas on.
    ///
    /// Before Gloas a block carries its payload, and no bid.
    fn payload_bid(_block: &Self::Block) -> Option<&ExecutionPayloadBid> {
        None
    }

    /// The domain a voluntary exit is signed in.
    ///
    /// Phase0 signs in the fork of the exit's epoch.
    /// See `validate_voluntary_exit_gossip` in the phase0 p2p spec.
    #[must_use]
    fn exit_domain(
        state: &combined::BeaconState<Self::Preset>,
        _config: &ChainConfig,
        epoch: Epoch,
    ) -> Domain {
        state.domain(DOMAIN_VOLUNTARY_EXIT, epoch)
    }

    /// The verdict on a block whose parent was seen but failed to import.
    ///
    /// Phase0 rejects it outright.
    fn failed_parent(_view: &ChainView<'_, Self::Preset>, _block: &Self::Block) -> GossipError {
        GossipError::reject("block's parent is invalid")
    }

    /// Checks a block's execution payload against the head state and its parent's payload.
    ///
    /// Phase0 blocks carry no payload.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the fork's rules say.
    fn check_execution(
        _view: &ChainView<'_, Self::Preset>,
        _head: &State<Self::Preset>,
        _block: &Self::Block,
    ) -> Verdict {
        Ok(())
    }

    /// Checks the block body's own limits, such as its blob count.
    ///
    /// Phase0 has none beyond the container's.
    ///
    /// # Errors
    ///
    /// Rejects a body over a limit.
    fn check_body(_config: &ChainConfig, _block: &Self::Block) -> Verdict {
        Ok(())
    }

    /// Checks a block against its parent's state, advanced to the block's slot.
    ///
    /// Phase0 checks only the proposer there, which every fork shares.
    ///
    /// # Errors
    ///
    /// Rejects a block that does not build on its parent as the fork requires.
    fn check_parent_state(
        _view: &ChainView<'_, Self::Preset>,
        _block: &Self::Block,
        _parent_state: &State<Self::Preset>,
    ) -> Verdict {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_fork_reads_the_data_index_its_own_way() {
        // Before Electra the index names the committee, so any value passes here.
        assert_eq!(VoteIndex::Committee.aggregate_violation(5), None);

        // Electra moved the committee out, so only zero is allowed.
        assert_eq!(VoteIndex::Zero.attestation_violation(0), None);
        assert_eq!(
            VoteIndex::Zero.attestation_violation(1),
            Some("attestation data index is non-zero")
        );

        // Gloas reads zero or one as the payload's presence, and nothing above.
        assert_eq!(VoteIndex::PayloadPresence.aggregate_violation(1), None);
        assert_eq!(
            VoteIndex::PayloadPresence.aggregate_violation(2),
            Some("aggregate data index must be 0 or 1")
        );
    }
}
