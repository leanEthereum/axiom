//! A beacon state of any fork.

use axiom_ssz::{CapacityError, DecodeError, GeneralizedIndex, MerkleProof, Root, Ssz};

use crate::{
    ChainConfig, ForkName, Gwei, Hash32, Preset, Slot,
    accessors::{CoreState, SyncCommitteeState},
    altair, bellatrix, capella, deneb, electra, fulu, gloas, phase0,
    phase0::{
        BeaconBlockHeader, BlockRoots, Checkpoint, Eth1Data, Eth1DataVotes, Fork, HistoricalRoots,
        JustificationBits, RandaoMixes, Slashings, StateRoots, Validator,
    },
};

/// Bytes before the slot in every state's encoding: the genesis time and validators root.
const SLOT_OFFSET: usize = 8 + 32;

/// A beacon state of whichever fork it belongs to.
///
/// Code that runs a fork's rules matches once and works on the concrete state.
/// The methods here are the few that every fork answers the same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconState<P: Preset> {
    /// A phase0 state.
    Phase0(phase0::BeaconState<P>),
    /// An Altair state.
    Altair(altair::BeaconState<P>),
    /// A Bellatrix state.
    Bellatrix(bellatrix::BeaconState<P>),
    /// A Capella state.
    Capella(capella::BeaconState<P>),
    /// A Deneb state.
    Deneb(deneb::BeaconState<P>),
    /// An Electra state.
    Electra(electra::BeaconState<P>),
    /// A Fulu state.
    Fulu(fulu::BeaconState<P>),
    /// A Gloas state.
    Gloas(gloas::BeaconState<P>),
}

impl<P: Preset> BeaconState<P> {
    /// Merkle commitment to the state, which blocks name as their state root.
    #[must_use]
    pub fn hash_tree_root(&self) -> Root {
        match self {
            Self::Phase0(state) => state.hash_tree_root(),
            Self::Altair(state) => state.hash_tree_root(),
            Self::Bellatrix(state) => state.hash_tree_root(),
            Self::Capella(state) => state.hash_tree_root(),
            Self::Deneb(state) => state.hash_tree_root(),
            Self::Electra(state) => state.hash_tree_root(),
            Self::Fulu(state) => state.hash_tree_root(),
            Self::Gloas(state) => state.hash_tree_root(),
        }
    }

    /// The node at a generalized index and its proof up to the state root.
    ///
    /// Light client data proves sync committees and the finalized root this way.
    /// Returns nothing when the index is outside the state's tree.
    #[must_use]
    pub fn prove(&self, index: GeneralizedIndex) -> Option<(Root, MerkleProof)> {
        match self {
            Self::Phase0(state) => state.prove(index),
            Self::Altair(state) => state.prove(index),
            Self::Bellatrix(state) => state.prove(index),
            Self::Capella(state) => state.prove(index),
            Self::Deneb(state) => state.prove(index),
            Self::Electra(state) => state.prove(index),
            Self::Fulu(state) => state.prove(index),
            Self::Gloas(state) => state.prove(index),
        }
    }

    /// The state's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Phase0(state) => state.encode(),
            Self::Altair(state) => state.encode(),
            Self::Bellatrix(state) => state.encode(),
            Self::Capella(state) => state.encode(),
            Self::Deneb(state) => state.encode(),
            Self::Electra(state) => state.encode(),
            Self::Fulu(state) => state.encode(),
            Self::Gloas(state) => state.encode(),
        }
    }

    /// Decodes a state of a known fork.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of a state of that fork.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        Ok(match fork {
            ForkName::Phase0 => Self::Phase0(Ssz::decode(bytes)?),
            ForkName::Altair => Self::Altair(Ssz::decode(bytes)?),
            ForkName::Bellatrix => Self::Bellatrix(Ssz::decode(bytes)?),
            ForkName::Capella => Self::Capella(Ssz::decode(bytes)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
            ForkName::Gloas => Self::Gloas(Ssz::decode(bytes)?),
        })
    }

    /// Decodes a state of the fork its own slot falls in.
    ///
    /// Every fork puts the slot at the same place, so it can be read before the fork is known.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are too short to hold a slot, or do not decode as that fork's state.
    pub fn decode_at(bytes: &[u8], config: &ChainConfig) -> Result<Self, DecodeError> {
        let slot = Slot::decode_at(bytes, SLOT_OFFSET)?;
        Self::decode(bytes, config.fork_at(slot.epoch::<P>()))
    }

    /// The state as the core every fork shares.
    ///
    /// The core trait is also implemented here, through this view.
    #[must_use]
    pub fn as_core(&self) -> &dyn CoreState<Preset = P> {
        match self {
            Self::Phase0(state) => state,
            Self::Altair(state) => state,
            Self::Bellatrix(state) => state,
            Self::Capella(state) => state,
            Self::Deneb(state) => state,
            Self::Electra(state) => state,
            Self::Fulu(state) => state,
            Self::Gloas(state) => state,
        }
    }

    /// The state as the core every fork shares, for edits.
    pub fn as_core_mut(&mut self) -> &mut dyn CoreState<Preset = P> {
        match self {
            Self::Phase0(state) => state,
            Self::Altair(state) => state,
            Self::Bellatrix(state) => state,
            Self::Capella(state) => state,
            Self::Deneb(state) => state,
            Self::Electra(state) => state,
            Self::Fulu(state) => state,
            Self::Gloas(state) => state,
        }
    }

    /// The sync committees, from Altair on.
    #[must_use]
    pub fn sync_committees(&self) -> Option<&dyn SyncCommitteeState<Preset = P>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(state) => Some(state),
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
            Self::Electra(state) => Some(state),
            Self::Fulu(state) => Some(state),
            Self::Gloas(state) => Some(state),
        }
    }

    /// Hash of the latest execution block the chain accepted, from Bellatrix on.
    ///
    /// Bellatrix through Fulu read it from the payload header, Gloas keeps it on its own.
    #[must_use]
    pub const fn latest_execution_block_hash(&self) -> Option<Hash32> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(state) => Some(state.latest_execution_payload_header.block_hash),
            Self::Capella(state) => Some(state.latest_execution_payload_header.block_hash),
            Self::Deneb(state) => Some(state.latest_execution_payload_header.block_hash),
            Self::Electra(state) => Some(state.latest_execution_payload_header.block_hash),
            Self::Fulu(state) => Some(state.latest_execution_payload_header.block_hash),
            Self::Gloas(state) => Some(state.latest_block_hash),
        }
    }

    /// Whether the chain has accepted its first execution payload.
    ///
    /// Before Bellatrix there is none, and Gloas starts long after the merge.
    /// See `is_merge_transition_complete` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn is_merge_transition_complete(&self) -> bool {
        match self {
            Self::Phase0(_) | Self::Altair(_) => false,
            Self::Bellatrix(state) => {
                state.latest_execution_payload_header
                    != bellatrix::ExecutionPayloadHeader::default()
            }
            Self::Capella(state) => {
                state.latest_execution_payload_header != capella::ExecutionPayloadHeader::default()
            }
            Self::Deneb(state) => {
                state.latest_execution_payload_header != deneb::ExecutionPayloadHeader::default()
            }
            Self::Electra(state) => {
                state.latest_execution_payload_header != electra::ExecutionPayloadHeader::default()
            }
            Self::Fulu(state) => {
                state.latest_execution_payload_header != fulu::ExecutionPayloadHeader::default()
            }
            Self::Gloas(_) => true,
        }
    }
}

impl<P: Preset> CoreState for BeaconState<P> {
    type Preset = P;

    fn fork_name(&self) -> ForkName {
        self.as_core().fork_name()
    }

    fn state_root(&self) -> Root {
        self.as_core().state_root()
    }

    fn genesis_time(&self) -> u64 {
        self.as_core().genesis_time()
    }

    fn genesis_validators_root(&self) -> Root {
        self.as_core().genesis_validators_root()
    }

    fn slot(&self) -> Slot {
        self.as_core().slot()
    }

    fn slot_mut(&mut self) -> &mut Slot {
        self.as_core_mut().slot_mut()
    }

    fn fork(&self) -> &Fork {
        self.as_core().fork()
    }

    fn latest_block_header(&self) -> &BeaconBlockHeader {
        self.as_core().latest_block_header()
    }

    fn latest_block_header_mut(&mut self) -> &mut BeaconBlockHeader {
        self.as_core_mut().latest_block_header_mut()
    }

    fn block_roots(&self) -> &BlockRoots<P> {
        self.as_core().block_roots()
    }

    fn block_roots_mut(&mut self) -> &mut BlockRoots<P> {
        self.as_core_mut().block_roots_mut()
    }

    fn state_roots(&self) -> &StateRoots<P> {
        self.as_core().state_roots()
    }

    fn state_roots_mut(&mut self) -> &mut StateRoots<P> {
        self.as_core_mut().state_roots_mut()
    }

    fn historical_roots(&self) -> &HistoricalRoots<P> {
        self.as_core().historical_roots()
    }

    fn historical_roots_mut(&mut self) -> &mut HistoricalRoots<P> {
        self.as_core_mut().historical_roots_mut()
    }

    fn eth1_data(&self) -> &Eth1Data {
        self.as_core().eth1_data()
    }

    fn eth1_data_mut(&mut self) -> &mut Eth1Data {
        self.as_core_mut().eth1_data_mut()
    }

    fn eth1_data_votes(&self) -> &Eth1DataVotes<P> {
        self.as_core().eth1_data_votes()
    }

    fn eth1_data_votes_mut(&mut self) -> &mut Eth1DataVotes<P> {
        self.as_core_mut().eth1_data_votes_mut()
    }

    fn eth1_deposit_index(&self) -> u64 {
        self.as_core().eth1_deposit_index()
    }

    fn eth1_deposit_index_mut(&mut self) -> &mut u64 {
        self.as_core_mut().eth1_deposit_index_mut()
    }

    fn validators(&self) -> &[Validator] {
        self.as_core().validators()
    }

    fn validators_mut(&mut self) -> &mut [Validator] {
        self.as_core_mut().validators_mut()
    }

    fn balances(&self) -> &[Gwei] {
        self.as_core().balances()
    }

    fn balances_mut(&mut self) -> &mut [Gwei] {
        self.as_core_mut().balances_mut()
    }

    fn push_validator(&mut self, validator: Validator, balance: Gwei) -> Result<(), CapacityError> {
        self.as_core_mut().push_validator(validator, balance)
    }

    fn randao_mixes(&self) -> &RandaoMixes<P> {
        self.as_core().randao_mixes()
    }

    fn randao_mixes_mut(&mut self) -> &mut RandaoMixes<P> {
        self.as_core_mut().randao_mixes_mut()
    }

    fn slashings(&self) -> &Slashings<P> {
        self.as_core().slashings()
    }

    fn slashings_mut(&mut self) -> &mut Slashings<P> {
        self.as_core_mut().slashings_mut()
    }

    fn justification_bits(&self) -> &JustificationBits {
        self.as_core().justification_bits()
    }

    fn justification_bits_mut(&mut self) -> &mut JustificationBits {
        self.as_core_mut().justification_bits_mut()
    }

    fn previous_justified_checkpoint(&self) -> Checkpoint {
        self.as_core().previous_justified_checkpoint()
    }

    fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        self.as_core_mut().previous_justified_checkpoint_mut()
    }

    fn current_justified_checkpoint(&self) -> Checkpoint {
        self.as_core().current_justified_checkpoint()
    }

    fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        self.as_core_mut().current_justified_checkpoint_mut()
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        self.as_core().finalized_checkpoint()
    }

    fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint {
        self.as_core_mut().finalized_checkpoint_mut()
    }
}

impl<P: Preset> From<phase0::BeaconState<P>> for BeaconState<P> {
    fn from(state: phase0::BeaconState<P>) -> Self {
        Self::Phase0(state)
    }
}

impl<P: Preset> From<altair::BeaconState<P>> for BeaconState<P> {
    fn from(state: altair::BeaconState<P>) -> Self {
        Self::Altair(state)
    }
}

impl<P: Preset> From<bellatrix::BeaconState<P>> for BeaconState<P> {
    fn from(state: bellatrix::BeaconState<P>) -> Self {
        Self::Bellatrix(state)
    }
}

impl<P: Preset> From<capella::BeaconState<P>> for BeaconState<P> {
    fn from(state: capella::BeaconState<P>) -> Self {
        Self::Capella(state)
    }
}

impl<P: Preset> From<deneb::BeaconState<P>> for BeaconState<P> {
    fn from(state: deneb::BeaconState<P>) -> Self {
        Self::Deneb(state)
    }
}

impl<P: Preset> From<electra::BeaconState<P>> for BeaconState<P> {
    fn from(state: electra::BeaconState<P>) -> Self {
        Self::Electra(state)
    }
}

impl<P: Preset> From<fulu::BeaconState<P>> for BeaconState<P> {
    fn from(state: fulu::BeaconState<P>) -> Self {
        Self::Fulu(state)
    }
}

impl<P: Preset> From<gloas::BeaconState<P>> for BeaconState<P> {
    fn from(state: gloas::BeaconState<P>) -> Self {
        Self::Gloas(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epoch, Minimal};

    #[test]
    fn decode_at_reads_the_fork_from_the_slot() {
        // Fixture state: Altair from epoch 1, so slot 8 of the minimal preset is Altair.
        let config = ChainConfig {
            altair_fork_epoch: Epoch(1),
            ..ChainConfig::minimal()
        };
        let state = altair::BeaconState::<Minimal> {
            slot: Slot(8),
            ..Default::default()
        };

        let decoded = BeaconState::<Minimal>::decode_at(&state.encode(), &config).unwrap();

        assert_eq!(decoded, BeaconState::Altair(state));
        assert_eq!(decoded.fork_name(), ForkName::Altair);
        assert_eq!(decoded.slot(), Slot(8));
    }

    #[test]
    fn decode_at_rejects_input_without_a_slot() {
        assert_eq!(
            BeaconState::<Minimal>::decode_at(&[0; 47], &ChainConfig::minimal()),
            Err(DecodeError::TooShort {
                minimum: 48,
                actual: 47
            })
        );
    }

    #[test]
    fn the_core_view_reads_and_writes_the_concrete_state() {
        // Fixture state: a Bellatrix state at slot 5 whose payload header names block hash 0x11.
        let mut bellatrix = bellatrix::BeaconState::<Minimal> {
            slot: Slot(5),
            ..Default::default()
        };
        bellatrix.latest_execution_payload_header.block_hash = Hash32([0x11; 32]);
        let mut state = BeaconState::from(bellatrix);

        // The core view answers for the variant, and edits land in it.
        assert_eq!(state.fork_name(), ForkName::Bellatrix);
        *state.slot_mut() = Slot(6);
        assert_eq!(state.slot(), Slot(6));
        assert_eq!(state.state_root(), state.hash_tree_root());

        // Bellatrix has sync committees and an execution block hash.
        assert!(state.sync_committees().is_some());
        assert_eq!(
            state.latest_execution_block_hash(),
            Some(Hash32([0x11; 32]))
        );
    }

    #[test]
    fn optional_groups_follow_the_fork() {
        // Phase0 has neither sync committees nor an execution chain.
        let phase0 = BeaconState::<Minimal>::from(phase0::BeaconState::default());
        assert!(phase0.sync_committees().is_none());
        assert_eq!(phase0.latest_execution_block_hash(), None);

        // Gloas keeps the latest block hash on its own, without a payload header.
        let gloas = BeaconState::<Minimal>::from(gloas::BeaconState {
            latest_block_hash: Hash32([0x22; 32]),
            ..Default::default()
        });
        assert_eq!(
            gloas.latest_execution_block_hash(),
            Some(Hash32([0x22; 32]))
        );
    }

    #[test]
    fn encoding_round_trips_through_the_fork() {
        // A default Gloas state, decoded back as Gloas.
        let state = BeaconState::<Minimal>::Gloas(gloas::BeaconState::default());

        let decoded = BeaconState::<Minimal>::decode(&state.encode(), ForkName::Gloas).unwrap();

        assert_eq!(decoded.hash_tree_root(), state.hash_tree_root());
        assert_eq!(decoded, state);
    }
}
