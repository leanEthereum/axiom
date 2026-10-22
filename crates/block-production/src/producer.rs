//! The block producer: one dispatch on the fork, then that fork's assembly.

use axiom_bls::Signature;
use axiom_operation_pool::OperationPool;
use axiom_ssz::Ssz;
use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, Bytes32, ChainConfig, ForkName, Gwei, Preset, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    altair, bellatrix,
    capella::{self, Withdrawal},
    constants::DOMAIN_RANDAO,
    deneb, electra, fulu, gloas, phase0,
    phase0::{Deposit, SigningData},
};

use crate::{
    BlockFork, BodyParts, Built, Eth1Candidate, Eth1Vote, ExecutionChoice, ParentPayload,
    ProductionError, Proposal, Trial,
};

/// Whether to check the randao reveal before building on it.
///
/// A distributed validator may only learn its reveal later, so the API lets it skip the check.
/// See the `skip_randao_verification` parameter of the block production route in beacon-APIs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RandaoCheck {
    /// Check the reveal against the proposer's key.
    #[default]
    Verify,
    /// Take the reveal as given.
    Skip,
}

/// What the proposer brings to a block, and the payload chosen for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRequest<P: Preset> {
    /// The slot to propose in.
    pub slot: Slot,
    /// The proposer's signature over the slot's epoch.
    pub randao_reveal: BlsSignature,
    /// Whether to check the reveal.
    pub randao: RandaoCheck,
    /// Free-form bytes of the proposer's choosing.
    pub graffiti: Bytes32,
    /// The execution chain the eth1 vote picks from, in height order.
    pub eth1_chain: Vec<Eth1Candidate>,
    /// The deposits due, with their proofs, in tree order.
    pub deposits: Vec<Deposit>,
    /// The payload, or the bid, the block commits to.
    pub execution: ExecutionChoice<P>,
}

/// What an execution engine needs to build a payload for a slot.
///
/// The node turns it into the payload attributes of its fork's engine method.
/// See `prepare_execution_payload` in the Bellatrix to Gloas validator specs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadRequest {
    /// The slot of the payload.
    pub slot: Slot,
    /// Start of the slot, in seconds since the Unix epoch.
    pub timestamp: u64,
    /// The randomness the payload exposes.
    pub prev_randao: Bytes32,
    /// The withdrawals the payload must carry, from Capella on.
    pub withdrawals: Vec<Withdrawal>,
    /// Root of the parent beacon block, from Deneb on.
    pub parent_beacon_block_root: Root,
}

/// Builds blocks on parent states, packing operations from a pool.
///
/// # Overview
///
/// 1. Advance the parent's state to the slot, and elect the proposer.
/// 2. Check the reveal, vote on eth1 data, and pack the operations.
/// 3. Hand the parts to the fork, which assembles the block and settles its state root.
/// 4. Report what the block pays its proposer, from the trial's balance change.
///
/// Nothing here signs: the validator client signs the block it receives.
#[derive(Clone, Copy, Debug)]
pub struct BlockProducer<'a, P: Preset> {
    /// The chain configuration.
    config: &'a ChainConfig,
    /// The operations to pack.
    pool: &'a OperationPool<P>,
}

impl<'a, P: Preset> BlockProducer<'a, P> {
    /// A producer under a configuration, packing from a pool.
    #[must_use]
    pub const fn new(config: &'a ChainConfig, pool: &'a OperationPool<P>) -> Self {
        Self { config, pool }
    }

    /// Builds the block of a slot on its parent's post-state.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the parent, the reveal does not verify, or the block is invalid.
    pub fn produce(
        &self,
        parent: &State<P>,
        request: ProposalRequest<P>,
    ) -> Result<Proposal<P>, ProductionError> {
        let state = self.advance(parent, request.slot)?;
        match state.fork_name() {
            ForkName::Phase0 => self.produce_in::<phase0::BeaconState<P>>(state, request),
            ForkName::Altair => self.produce_in::<altair::BeaconState<P>>(state, request),
            ForkName::Bellatrix => self.produce_in::<bellatrix::BeaconState<P>>(state, request),
            ForkName::Capella => self.produce_in::<capella::BeaconState<P>>(state, request),
            ForkName::Deneb => self.produce_in::<deneb::BeaconState<P>>(state, request),
            ForkName::Electra => self.produce_in::<electra::BeaconState<P>>(state, request),
            ForkName::Fulu => self.produce_in::<fulu::BeaconState<P>>(state, request),
            ForkName::Gloas => self.produce_in::<gloas::BeaconState<P>>(state, request),
        }
    }

    /// What the engine needs to build the payload of a slot on a parent.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the parent, or the withdrawals cannot be computed.
    pub fn payload_request(
        &self,
        parent: &State<P>,
        slot: Slot,
        parent_payload: &ParentPayload,
    ) -> Result<PayloadRequest, ProductionError> {
        let state = self.advance(parent, slot)?;
        let trial = Trial::new(&state, self.config);
        let withdrawals = match state.fork_name() {
            ForkName::Phase0 => phase0::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
            ForkName::Altair => altair::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
            ForkName::Bellatrix => {
                bellatrix::BeaconState::<P>::withdrawals_due(&trial, parent_payload)
            }
            ForkName::Capella => capella::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
            ForkName::Deneb => deneb::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
            ForkName::Electra => electra::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
            ForkName::Fulu => fulu::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
            ForkName::Gloas => gloas::BeaconState::<P>::withdrawals_due(&trial, parent_payload),
        }?;
        let beacon = state.beacon();
        Ok(PayloadRequest {
            slot,
            timestamp: beacon.genesis_time() + slot.0 * self.config.slot_duration_ms / 1000,
            prev_randao: beacon.randao_mix(beacon.current_epoch()),
            withdrawals,
            parent_beacon_block_root: beacon.latest_block_header().hash_tree_root(),
        })
    }

    /// The parent's state advanced to the slot.
    fn advance(&self, parent: &State<P>, slot: Slot) -> Result<State<P>, ProductionError> {
        let parent_slot = parent.beacon().slot();
        let mut state = parent.clone();
        if slot > parent_slot {
            state
                .process_slots(self.config, slot)
                .map_err(|source| ProductionError::Slots { slot, source })?;
        } else if slot < parent_slot || parent.beacon().latest_block_header().slot == slot {
            return Err(ProductionError::SlotNotAfterParent {
                slot,
                parent: parent_slot,
            });
        }
        Ok(state)
    }

    /// Builds the block under one fork's rules.
    fn produce_in<S: BlockFork<Preset = P>>(
        &self,
        mut state: State<P>,
        request: ProposalRequest<P>,
    ) -> Result<Proposal<P>, ProductionError> {
        let slot = request.slot;
        let proposer_index = state
            .beacon_proposer_index()
            .map_err(|source| ProductionError::Proposer { slot, source })?;
        if request.randao == RandaoCheck::Verify {
            Self::verify_randao(&mut state, proposer_index, request.randao_reveal)?;
        }
        let beacon = S::from_any(state.beacon()).ok_or(ProductionError::WrongState(S::FORK))?;
        let eth1_data = Eth1Vote::new(self.config).choose(
            beacon,
            &request.eth1_chain,
            S::bridge_closed(beacon),
        );
        // Invariant: slot processing filled the parent header's state root, so this is its root.
        let parent_root = state.beacon().latest_block_header().hash_tree_root();

        let trial = Trial::new(&state, self.config);
        let packing = S::packing_state(&trial, &request.execution)?;
        let operations = self
            .pool
            .pack::<S>(packing.as_ref().unwrap_or(&state), self.config)?;
        let previous_slot = Slot(slot.0.saturating_sub(1));
        let parts = BodyParts {
            slot,
            proposer_index,
            parent_root,
            randao_reveal: request.randao_reveal,
            eth1_data,
            graffiti: request.graffiti,
            deposits: request.deposits,
            operations,
            sync_aggregate: self
                .pool
                .sync()
                .sync_aggregate(previous_slot, parent_root)?,
            payload_attestations: self.pool.payload_attestations().for_block(
                previous_slot,
                parent_root,
                P::MAX_PAYLOAD_ATTESTATIONS as usize,
            )?,
        };

        let execution_value = request.execution.value();
        let before = Self::balance(&state, proposer_index);
        let Built { block, post } = S::build(&trial, &parts, request.execution)?;
        let consensus_value = Gwei(
            Self::balance(&post, proposer_index)
                .0
                .saturating_sub(before.0),
        );
        Ok(Proposal {
            block,
            consensus_value,
            execution_value,
        })
    }

    /// Checks the reveal is the proposer's signature over the epoch.
    ///
    /// See `process_randao` in the phase0 beacon chain spec.
    fn verify_randao(
        state: &mut State<P>,
        proposer: ValidatorIndex,
        reveal: BlsSignature,
    ) -> Result<(), ProductionError> {
        let slot = state.beacon().slot();
        let epoch = slot.epoch::<P>();
        let root = SigningData::signing_root(&epoch, state.beacon().domain(DOMAIN_RANDAO, epoch));
        let key = state
            .public_key(proposer)
            .map_err(|source| ProductionError::Proposer { slot, source })?;
        // A reveal that is not even a point fails like a wrong one.
        let verified = Signature::from_bytes(&reveal.0)
            .is_ok_and(|signature| signature.verify(&key, root.as_ref()));
        if verified {
            Ok(())
        } else {
            Err(ProductionError::InvalidRandao { slot, proposer })
        }
    }

    /// A validator's balance, zero when it does not exist.
    fn balance(state: &State<P>, index: ValidatorIndex) -> Gwei {
        state
            .beacon()
            .balances()
            .get(index.as_usize())
            .copied()
            .unwrap_or_default()
    }
}
