//! Every pool of operations, and the packing of a block's operations from them.

use std::sync::Arc;

use axiom_state_transition::{BlockProcessor, EpochCommittees, State, Verification};
use axiom_types::{
    ChainConfig, CommitteeIndex, Preset, Slot, ValidatorIndex,
    accessors::CoreState,
    capella::SignedBlsToExecutionChange,
    phase0::{ProposerSlashing, SignedVoluntaryExit},
};

use crate::{
    AttestationPacker, AttestationPool, PayloadAttestationPool, PoolError, PoolFork, SlashingPool,
    SyncPool, ValidatorRequests,
};

/// The operations of one block, in the containers of the block's fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockOperations<S: PoolFork> {
    /// Proposer slashings.
    pub proposer_slashings: Vec<ProposerSlashing>,
    /// Attester slashings.
    pub attester_slashings: Vec<S::AttesterSlashing>,
    /// Attestations, the best first.
    pub attestations: Vec<S::Attestation>,
    /// Voluntary exits.
    pub voluntary_exits: Vec<SignedVoluntaryExit>,
    /// Withdrawal credential changes, none before Capella.
    pub bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
}

/// The operations a node keeps for the blocks its validators propose.
///
/// # Overview
///
/// Each kind of operation has its pool, with its own entry checks.
/// Packing then asks the fork of the block what it may carry, at the state of the block's slot.
///
/// 1. Attestations go through a weighted maximum coverage of the rewards left.
/// 2. Slashings, exits, and credential changes are applied in block order to a copy of the state.
///    Each one that the fork's rule refuses is left out.
///
/// Finality prunes what the finalized state already carried out.
/// Each new slot prunes the votes no block can include any more.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationPool<P: Preset> {
    /// Attestations.
    attestations: AttestationPool,
    /// Proposer and attester slashings.
    slashings: SlashingPool,
    /// Voluntary exits and credential changes.
    requests: ValidatorRequests,
    /// Sync committee signatures.
    sync: SyncPool<P>,
    /// Payload timeliness votes.
    payload_attestations: PayloadAttestationPool,
}

impl<P: Preset> OperationPool<P> {
    /// The attestations.
    #[must_use]
    pub const fn attestations(&self) -> &AttestationPool {
        &self.attestations
    }

    /// The attestations, to add votes.
    pub const fn attestations_mut(&mut self) -> &mut AttestationPool {
        &mut self.attestations
    }

    /// The slashings.
    #[must_use]
    pub const fn slashings(&self) -> &SlashingPool {
        &self.slashings
    }

    /// The slashings, to add evidence.
    pub const fn slashings_mut(&mut self) -> &mut SlashingPool {
        &mut self.slashings
    }

    /// The exits and credential changes.
    #[must_use]
    pub const fn requests(&self) -> &ValidatorRequests {
        &self.requests
    }

    /// The exits and credential changes, to add requests.
    pub const fn requests_mut(&mut self) -> &mut ValidatorRequests {
        &mut self.requests
    }

    /// The sync committee signatures.
    #[must_use]
    pub const fn sync(&self) -> &SyncPool<P> {
        &self.sync
    }

    /// The sync committee signatures, to add messages.
    pub const fn sync_mut(&mut self) -> &mut SyncPool<P> {
        &mut self.sync
    }

    /// The payload timeliness votes.
    #[must_use]
    pub const fn payload_attestations(&self) -> &PayloadAttestationPool {
        &self.payload_attestations
    }

    /// The payload timeliness votes, to add messages.
    pub const fn payload_attestations_mut(&mut self) -> &mut PayloadAttestationPool {
        &mut self.payload_attestations
    }

    /// Drops what no block from a slot on can include.
    pub fn on_slot(&mut self, slot: Slot) {
        self.attestations.prune::<P>(slot.epoch::<P>());
        self.sync.prune(slot);
        self.payload_attestations.prune(slot);
    }

    /// Drops what a finalized state already carried out.
    pub fn on_finalized<S: CoreState>(&mut self, state: &S) {
        self.slashings.prune(state);
        self.requests.prune(state);
    }

    /// The operations of a block of one fork, for the state at the block's slot.
    ///
    /// The state must hold whatever the block applies before its operations.
    /// In Gloas that is the parent's payload, which can change what an exit may do.
    ///
    /// # Errors
    ///
    /// Fails when the state is of another fork, or its committees cannot be computed.
    pub fn pack<S: PoolFork<Preset = P>>(
        &self,
        state: &State<P>,
        config: &ChainConfig,
    ) -> Result<BlockOperations<S>, PoolError> {
        let mut trial = state.clone();
        let fork = trial.fork_name();
        let mut cached = trial.of_fork::<S>().ok_or(PoolError::WrongFork {
            expected: S::FORK,
            actual: fork,
        })?;

        // Phase 1: attestations, by maximum coverage over the credits left.
        let ledger = S::ledger(&mut cached)?;
        let epochs = [
            cached.beacon().previous_epoch(),
            cached.beacon().current_epoch(),
        ];
        let committees: Vec<Arc<EpochCommittees>> = epochs
            .into_iter()
            .map(|epoch| cached.committees(epoch))
            .collect::<Result<_, _>>()?;
        let beacon = cached.beacon();
        let committee = |slot: Slot, index: CommitteeIndex| -> Option<Vec<ValidatorIndex>> {
            let epoch = slot.epoch::<P>();
            committees
                .iter()
                .find(|committees| committees.epoch() == epoch)?
                .committee(slot, index)
                .map(<[ValidatorIndex]>::to_vec)
        };
        let packed = AttestationPacker::new(beacon, &ledger).pack(
            &self.attestations,
            |data| S::eligibility(beacon, data),
            committee,
            S::ATTESTATION_LIMIT as usize,
        )?;
        let attestations = packed
            .into_iter()
            .map(S::attestation)
            .collect::<Result<Vec<_>, _>>()?;

        // Phase 2: the other operations, applied in block order.
        // Why: each of these rules checks every condition before it writes to the state.
        // A refused operation therefore leaves the copy untouched for the next one.
        let mut processor = BlockProcessor::new(cached, config, Verification::Skip);
        let proposer_slashings: Vec<ProposerSlashing> = self
            .slashings
            .proposers()
            .filter(|slashing| processor.apply(*slashing).is_ok())
            .take(P::MAX_PROPOSER_SLASHINGS as usize)
            .cloned()
            .collect();
        let mut attester_slashings = Vec::new();
        for votes in self
            .slashings
            .attesters_by_reach(processor.state().beacon())
        {
            if attester_slashings.len() as u64 >= S::ATTESTER_SLASHING_LIMIT {
                break;
            }
            let Ok(slashing) = S::attester_slashing(votes) else {
                continue;
            };
            if S::apply_attester_slashing(&mut processor, &slashing).is_ok() {
                attester_slashings.push(slashing);
            }
        }
        let voluntary_exits: Vec<SignedVoluntaryExit> = self
            .requests
            .exits()
            .filter(|exit| S::apply_exit(&mut processor, exit).is_ok())
            .take(P::MAX_VOLUNTARY_EXITS as usize)
            .cloned()
            .collect();
        let bls_to_execution_changes: Vec<SignedBlsToExecutionChange> = self
            .requests
            .credential_changes()
            .take_while(|_| S::CREDENTIAL_CHANGE_LIMIT > 0)
            .filter(|change| processor.apply(*change).is_ok())
            .take(S::CREDENTIAL_CHANGE_LIMIT as usize)
            .cloned()
            .collect();
        Ok(BlockOperations {
            proposer_slashings,
            attester_slashings,
            attestations,
            voluntary_exits,
            bls_to_execution_changes,
        })
    }
}
