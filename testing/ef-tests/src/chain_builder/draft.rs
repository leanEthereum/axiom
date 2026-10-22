//! The inputs of the next block, and its assembly in the fork of its slot.

use axiom_ssz::Ssz;
use axiom_state_transition::{
    State, capella::block::ValidatorSweep, electra::block::ExpectedWithdrawals,
};
use axiom_types::{
    BlsSignature, Bytes32, ChainConfig, Hash32, Preset, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    altair, bellatrix,
    capella::{self, Withdrawal},
    combined,
    constants::{DOMAIN_RANDAO, G2_POINT_AT_INFINITY},
    deneb, electra, gloas,
    phase0::{self, Eth1Data, SigningData},
};

use crate::chain_builder::{ChainBuilderError, keyring::Keyring, payload::PayloadParts};

/// What the next block needs from the state at its slot, before any fork's body is chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Draft {
    /// The slot of the block.
    pub(crate) slot: Slot,
    /// The proposer the state elects for the slot.
    pub(crate) proposer_index: ValidatorIndex,
    /// Root of the latest block, whose state root slot processing filled in.
    pub(crate) parent_root: Root,
    /// The proposer's signature over the slot's epoch.
    reveal: BlsSignature,
    /// The state's eth1 vote, copied so the vote changes nothing.
    eth1_data: Eth1Data,
    /// The current epoch's randomness, before this block's reveal mixes in.
    prev_randao: Bytes32,
    /// Start of the slot, in seconds since the Unix epoch.
    timestamp: u64,
}

impl Draft {
    /// The inputs of the block for the slot a state was advanced to.
    ///
    /// The payload reads the randomness before the reveal: payload processing runs first.
    /// See `process_block` in the Capella beacon chain spec.
    pub(crate) fn new<P: Preset>(
        state: &State<P>,
        config: &ChainConfig,
        keyring: &Keyring,
    ) -> Result<Self, ChainBuilderError> {
        let beacon = state.beacon();
        let slot = beacon.slot();
        let proposer_index = state
            .beacon_proposer_index()
            .map_err(|source| ChainBuilderError::Inputs { slot, source })?;
        let epoch = slot.epoch::<P>();
        let reveal_root = SigningData::signing_root(&epoch, beacon.domain(DOMAIN_RANDAO, epoch));
        let reveal = keyring.sign(proposer_index, reveal_root)?;
        // Timing: genesis time plus the slot's whole milliseconds, truncated to seconds.
        let timestamp = beacon.genesis_time() + slot.0 * config.slot_duration_ms / 1000;
        Ok(Self {
            slot,
            proposer_index,
            parent_root: beacon.latest_block_header().hash_tree_root(),
            reveal,
            eth1_data: beacon.eth1_data().clone(),
            prev_randao: beacon.randao_mix(epoch),
            timestamp,
        })
    }

    /// The block of the state's fork, claiming a post-state root.
    ///
    /// Each fork's body carries no operations, so only the mandatory fields vary.
    /// Withdrawals come from the state, as each fork's withdrawal rule computes them.
    pub(crate) fn block<P: Preset>(
        &self,
        state: &combined::BeaconState<P>,
        state_root: Root,
    ) -> Result<combined::BeaconBlock<P>, ChainBuilderError> {
        let inputs = |source| ChainBuilderError::Inputs {
            slot: self.slot,
            source,
        };
        let block = match state {
            combined::BeaconState::Phase0(_) => {
                combined::BeaconBlock::Phase0(self.phase0_block(state_root))
            }
            combined::BeaconState::Altair(_) => {
                combined::BeaconBlock::Altair(self.altair_block(state_root))
            }
            combined::BeaconState::Bellatrix(_) => {
                combined::BeaconBlock::Bellatrix(self.bellatrix_block(state_root))
            }
            combined::BeaconState::Capella(state) => {
                let parent_hash = state.latest_execution_payload_header.block_hash;
                let withdrawals = ValidatorSweep::compute(state).map_err(inputs)?.withdrawals;
                let block = self.capella_block(parent_hash, withdrawals, state_root)?;
                combined::BeaconBlock::Capella(block)
            }
            combined::BeaconState::Deneb(state) => {
                let parent_hash = state.latest_execution_payload_header.block_hash;
                let withdrawals = ValidatorSweep::compute(state).map_err(inputs)?.withdrawals;
                let block = self.deneb_block(parent_hash, withdrawals, state_root)?;
                combined::BeaconBlock::Deneb(block)
            }
            combined::BeaconState::Electra(state) => {
                let parent_hash = state.latest_execution_payload_header.block_hash;
                let withdrawals = ExpectedWithdrawals::compute(state)
                    .map_err(inputs)?
                    .withdrawals;
                let block = self.electra_block(parent_hash, withdrawals, state_root)?;
                combined::BeaconBlock::Electra(block)
            }
            // Fulu kept Electra's block, and its withdrawal rule.
            combined::BeaconState::Fulu(state) => {
                let parent_hash = state.latest_execution_payload_header.block_hash;
                let withdrawals = ExpectedWithdrawals::compute(state)
                    .map_err(inputs)?
                    .withdrawals;
                let block = self.electra_block(parent_hash, withdrawals, state_root)?;
                combined::BeaconBlock::Fulu(block)
            }
            // Gloas fixes the withdrawals while processing the block, and the envelope pays them.
            combined::BeaconState::Gloas(state) => {
                let parent_hash = state.latest_execution_payload_bid.block_hash;
                combined::BeaconBlock::Gloas(self.gloas_block(parent_hash, state_root))
            }
        };
        Ok(block)
    }

    /// The phase0 block: the reveal and the eth1 vote.
    fn phase0_block<P: Preset>(&self, state_root: Root) -> phase0::BeaconBlock<P> {
        phase0::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: phase0::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                ..phase0::BeaconBlockBody::default()
            },
        }
    }

    /// The Altair block: phase0's, with an empty sync aggregate.
    fn altair_block<P: Preset>(&self, state_root: Root) -> altair::BeaconBlock<P> {
        altair::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: altair::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                sync_aggregate: Self::empty_sync_aggregate(),
                ..altair::BeaconBlockBody::default()
            },
        }
    }

    /// The Bellatrix block, before the merge.
    ///
    /// The default payload leaves execution disabled.
    /// See `is_execution_enabled` in the Bellatrix beacon chain spec.
    fn bellatrix_block<P: Preset>(&self, state_root: Root) -> bellatrix::BeaconBlock<P> {
        bellatrix::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: bellatrix::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                sync_aggregate: Self::empty_sync_aggregate(),
                execution_payload: bellatrix::ExecutionPayload::default(),
                ..bellatrix::BeaconBlockBody::default()
            },
        }
    }

    /// The Capella block, whose payload carries the withdrawals due.
    ///
    /// The first Capella payload extends the zero hash that a pre-merge header holds.
    fn capella_block<P: Preset>(
        &self,
        parent_hash: Hash32,
        withdrawals: Vec<Withdrawal>,
        state_root: Root,
    ) -> Result<capella::BeaconBlock<P>, ChainBuilderError> {
        Ok(capella::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: capella::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                sync_aggregate: Self::empty_sync_aggregate(),
                execution_payload: self.payload(parent_hash).capella(withdrawals)?,
                ..capella::BeaconBlockBody::default()
            },
        })
    }

    /// The Deneb block: no blob commitments.
    fn deneb_block<P: Preset>(
        &self,
        parent_hash: Hash32,
        withdrawals: Vec<Withdrawal>,
        state_root: Root,
    ) -> Result<deneb::BeaconBlock<P>, ChainBuilderError> {
        Ok(deneb::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: deneb::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                sync_aggregate: Self::empty_sync_aggregate(),
                execution_payload: self.payload(parent_hash).deneb(withdrawals)?,
                ..deneb::BeaconBlockBody::default()
            },
        })
    }

    /// The Electra block, which Fulu keeps: no blobs and no execution requests.
    fn electra_block<P: Preset>(
        &self,
        parent_hash: Hash32,
        withdrawals: Vec<Withdrawal>,
        state_root: Root,
    ) -> Result<electra::BeaconBlock<P>, ChainBuilderError> {
        Ok(electra::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: electra::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                sync_aggregate: Self::empty_sync_aggregate(),
                execution_payload: self.payload(parent_hash).deneb(withdrawals)?,
                ..electra::BeaconBlockBody::default()
            },
        })
    }

    /// The Gloas block, with a self-built bid in place of the payload.
    ///
    /// The bid extends the parent's payload, so the parent counts as full.
    /// That payload's envelope carried no requests, so the block reports none.
    /// See `process_parent_execution_payload` in the Gloas beacon chain spec.
    fn gloas_block<P: Preset>(
        &self,
        parent_hash: Hash32,
        state_root: Root,
    ) -> gloas::BeaconBlock<P> {
        gloas::BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body: gloas::BeaconBlockBody {
                randao_reveal: self.reveal,
                eth1_data: self.eth1_data.clone(),
                sync_aggregate: Self::empty_sync_aggregate(),
                signed_execution_payload_bid: self
                    .payload(parent_hash)
                    .self_built_bid(self.parent_root),
                parent_execution_requests: gloas::ExecutionRequests::default(),
                ..gloas::BeaconBlockBody::default()
            },
        }
    }

    /// The payload fields fixed by the slot, extending an execution block.
    pub(crate) const fn payload(&self, parent_hash: Hash32) -> PayloadParts {
        PayloadParts {
            slot: self.slot,
            parent_hash,
            prev_randao: self.prev_randao,
            timestamp: self.timestamp,
        }
    }

    /// A sync aggregate no member signed.
    ///
    /// The point at infinity is the valid signature of an empty aggregate.
    /// See `eth_fast_aggregate_verify` in the Altair BLS spec.
    fn empty_sync_aggregate<P: Preset>() -> altair::SyncAggregate<P> {
        altair::SyncAggregate {
            sync_committee_bits: altair::SyncCommitteeBits::<P>::default(),
            sync_committee_signature: G2_POINT_AT_INFINITY,
        }
    }
}
