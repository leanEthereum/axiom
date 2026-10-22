//! Evidence of slashable behaviour, waiting for a block to punish it.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
};

use axiom_types::{
    ValidatorIndex, accessors::CoreState, phase0::ProposerSlashing, vote::ConflictingVotes,
};

use crate::PoolError;

/// Proposer slashings by the proposer they punish, and attester slashings in arrival order.
///
/// # Overview
///
/// Entry checks only what can change the verdict without a signature.
/// That is the shape of the evidence, and whether someone is left to slash.
/// The caller checked every signature, as gossip rules do.
///
/// The block's own processing checks everything again at packing time.
///
/// # Invariants
///
/// One proposer slashing per proposer: a second adds nothing, since one slashing suffices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlashingPool {
    /// Proposer slashings by the proposer.
    proposers: BTreeMap<ValidatorIndex, ProposerSlashing>,
    /// Attester slashings, reduced to the fields every fork shares.
    attesters: Vec<ConflictingVotes>,
}

impl SlashingPool {
    /// Adds a proposer slashing whose signatures the caller verified.
    ///
    /// See `process_proposer_slashing` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the headers are not a double proposal, or the proposer cannot be slashed.
    pub fn insert_proposer<S: CoreState>(
        &mut self,
        state: &S,
        slashing: ProposerSlashing,
    ) -> Result<(), PoolError> {
        let first = &slashing.signed_header_1.message;
        let second = &slashing.signed_header_2.message;
        if first.slot != second.slot
            || first.proposer_index != second.proposer_index
            || first == second
        {
            return Err(PoolError::NotDoubleProposal {
                first: first.slot,
                second: second.slot,
            });
        }
        let proposer = first.proposer_index;
        if !Self::is_slashable(state, proposer)? {
            return Err(PoolError::AlreadyInEffect(proposer));
        }
        self.proposers.entry(proposer).or_insert(slashing);
        Ok(())
    }

    /// Adds an attester slashing whose signatures the caller verified.
    ///
    /// See `process_attester_slashing` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the votes do not conflict, or no common signer can be slashed.
    pub fn insert_attester<S: CoreState>(
        &mut self,
        state: &S,
        votes: ConflictingVotes,
    ) -> Result<(), PoolError> {
        if !votes.first.data.is_slashable_with(&votes.second.data) {
            return Err(PoolError::NotSlashable);
        }
        let slashable = Self::slashable_signers(state, &votes);
        if slashable.is_empty() {
            let first = votes.common_signers().first().copied().unwrap_or_default();
            return Err(PoolError::AlreadyInEffect(first));
        }
        // Evidence slashing nobody new beside what is pooled adds nothing.
        let pooled: BTreeSet<ValidatorIndex> = self
            .attesters
            .iter()
            .flat_map(ConflictingVotes::common_signers)
            .collect();
        if slashable.iter().all(|index| pooled.contains(index)) {
            return Ok(());
        }
        self.attesters.push(votes);
        Ok(())
    }

    /// The proposer slashings, by increasing proposer index.
    pub fn proposers(&self) -> impl Iterator<Item = &ProposerSlashing> {
        self.proposers.values()
    }

    /// The attester slashings, those slashing the most validators first.
    #[must_use]
    pub fn attesters_by_reach<S: CoreState>(&self, state: &S) -> Vec<&ConflictingVotes> {
        let mut ranked: Vec<(usize, &ConflictingVotes)> = self
            .attesters
            .iter()
            .map(|votes| (Self::slashable_signers(state, votes).len(), votes))
            .filter(|(reach, _)| *reach > 0)
            .collect();
        // Stable, so evidence of equal reach keeps its arrival order.
        ranked.sort_by_key(|(reach, _)| Reverse(*reach));
        ranked.into_iter().map(|(_, votes)| votes).collect()
    }

    /// Drops evidence against validators the state already slashed.
    pub fn prune<S: CoreState>(&mut self, state: &S) {
        self.proposers
            .retain(|index, _| Self::is_slashable(state, *index).unwrap_or(false));
        self.attesters
            .retain(|votes| !Self::slashable_signers(state, votes).is_empty());
    }

    /// Number of pooled slashings of both kinds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.proposers.len() + self.attesters.len()
    }

    /// Whether the pool holds no slashing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The common signers of two votes the state can still slash.
    fn slashable_signers<S: CoreState>(state: &S, votes: &ConflictingVotes) -> Vec<ValidatorIndex> {
        votes
            .common_signers()
            .into_iter()
            .filter(|index| Self::is_slashable(state, *index).unwrap_or(false))
            .collect()
    }

    /// Whether the state can slash a validator now.
    ///
    /// See `is_slashable_validator` in the phase0 beacon chain spec.
    fn is_slashable<S: CoreState>(state: &S, index: ValidatorIndex) -> Result<bool, PoolError> {
        let validators = state.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(PoolError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        Ok(validator.is_slashable_at(state.current_epoch()))
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        BlsSignature, Epoch, Minimal, Root, Slot,
        phase0::{
            self, AttestationData, BeaconBlockHeader, Checkpoint, SignedBeaconBlockHeader,
            Validator,
        },
        vote::IndexedVote,
    };

    use super::*;

    /// A phase0 state of four active, unslashed validators.
    fn state() -> phase0::BeaconState<Minimal> {
        let mut state = phase0::BeaconState::<Minimal>::default();
        for _ in 0..4 {
            let validator = Validator {
                activation_epoch: Epoch(0),
                exit_epoch: Epoch::FAR_FUTURE,
                withdrawable_epoch: Epoch::FAR_FUTURE,
                ..Validator::default()
            };
            state.validators.push(validator).unwrap();
        }
        state
    }

    /// A header of proposer 2 at slot 5, with a distinguishing state root.
    fn header(root: u8) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: Slot(5),
                proposer_index: ValidatorIndex(2),
                state_root: Root([root; 32]),
                ..BeaconBlockHeader::default()
            },
            signature: BlsSignature::default(),
        }
    }

    /// Two votes by validators 1 and 3 targeting epoch 1 with different roots.
    fn double_vote() -> ConflictingVotes {
        let vote = |root: u8| IndexedVote {
            indices: vec![ValidatorIndex(1), ValidatorIndex(3)],
            data: AttestationData {
                target: Checkpoint {
                    epoch: Epoch(1),
                    root: Root([root; 32]),
                },
                ..AttestationData::default()
            },
            signature: BlsSignature::default(),
        };
        ConflictingVotes {
            first: vote(1),
            second: vote(2),
        }
    }

    #[test]
    fn a_double_proposal_enters_once_per_proposer() {
        let state = state();
        let mut pool = SlashingPool::default();
        let slashing = ProposerSlashing {
            signed_header_1: header(1),
            signed_header_2: header(2),
        };

        pool.insert_proposer(&state, slashing.clone()).unwrap();
        // A second piece of evidence against proposer 2 is redundant.
        let other = ProposerSlashing {
            signed_header_2: header(3),
            ..slashing.clone()
        };
        pool.insert_proposer(&state, other).unwrap();

        assert_eq!(pool.proposers().collect::<Vec<_>>(), [&slashing]);
    }

    #[test]
    fn identical_headers_are_not_a_double_proposal() {
        // Mutation: both headers are the same block.
        let slashing = ProposerSlashing {
            signed_header_1: header(1),
            signed_header_2: header(1),
        };
        assert_eq!(
            SlashingPool::default().insert_proposer(&state(), slashing),
            Err(PoolError::NotDoubleProposal {
                first: Slot(5),
                second: Slot(5),
            })
        );
    }

    #[test]
    fn evidence_against_slashed_validators_is_refused_and_pruned() {
        let mut state = state();
        let mut pool = SlashingPool::default();
        pool.insert_attester(&state, double_vote()).unwrap();
        assert_eq!(pool.len(), 1);

        // Mutation: validators 1 and 3 are slashed by another block.
        for index in [1, 3] {
            state.validators[index].slashed = true;
        }
        pool.prune(&state);
        assert!(pool.is_empty());
        assert_eq!(
            pool.insert_attester(&state, double_vote()),
            Err(PoolError::AlreadyInEffect(ValidatorIndex(1)))
        );
    }

    #[test]
    fn votes_that_do_not_conflict_are_refused() {
        // Mutation: both votes carry the same data.
        let mut votes = double_vote();
        votes.second.data = votes.first.data.clone();
        assert_eq!(
            SlashingPool::default().insert_attester(&state(), votes),
            Err(PoolError::NotSlashable)
        );
    }
}
