//! The beacon state of phase0.

use axiom_ssz::{
    BitVector, CapacityError, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz,
    Vector,
};

use crate::{
    Bytes32, ForkName, Gwei, Preset, Root, Slot,
    accessors::{CoreState, ForkState},
    combined,
    constants::JUSTIFICATION_BITS_LENGTH,
    phase0::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork, PendingAttestation, Validator},
};

/// Recent block roots.
pub type BlockRoots<P> = Vector<Root, <P as Preset>::SlotsPerHistoricalRoot>;

/// Recent state roots.
pub type StateRoots<P> = Vector<Root, <P as Preset>::SlotsPerHistoricalRoot>;

/// Pre-Capella history accumulator.
pub type HistoricalRoots<P> = List<Root, <P as Preset>::HistoricalRootsLimit>;

/// Eth1 data votes of a voting period.
pub type Eth1DataVotes<P> = List<Eth1Data, <P as Preset>::Eth1DataVotesLimit>;

/// The validator registry.
pub type Validators<P> = List<Validator, <P as Preset>::ValidatorRegistryLimit>;

/// Validator balances.
pub type Balances<P> = List<Gwei, <P as Preset>::ValidatorRegistryLimit>;

/// Randao mixes by epoch.
pub type RandaoMixes<P> = Vector<Bytes32, <P as Preset>::EpochsPerHistoricalVector>;

/// Slashed balances by epoch.
pub type Slashings<P> = Vector<Gwei, <P as Preset>::EpochsPerSlashingsVector>;

/// Attestations of one epoch awaiting scoring.
pub type PendingAttestations<P> =
    List<PendingAttestation<P>, <P as Preset>::MaxPendingAttestations>;

/// Justification history of the last four epochs.
pub type JustificationBits = BitVector<Const<JUSTIFICATION_BITS_LENGTH>>;

/// The full consensus state at one slot.
///
/// Every block and epoch transition is a pure function from one state to the next.
/// See the phase0 beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BeaconState<P: Preset> {
    /// Unix time of genesis, in seconds.
    pub genesis_time: u64,

    /// Root of the genesis validator set, which identifies the chain.
    pub genesis_validators_root: Root,

    /// Slot the state is at.
    pub slot: Slot,

    /// Current and previous fork versions.
    pub fork: Fork,

    /// Header of the latest block, with its state root filled in one slot late.
    pub latest_block_header: BeaconBlockHeader,

    /// Recent block roots, a ring buffer indexed by slot.
    pub block_roots: BlockRoots<P>,

    /// Recent state roots, a ring buffer indexed by slot.
    pub state_roots: StateRoots<P>,

    /// Frozen pre-Capella history accumulator.
    pub historical_roots: HistoricalRoots<P>,

    /// Latest agreed deposit contract snapshot.
    pub eth1_data: Eth1Data,

    /// Eth1 data votes of the current voting period.
    pub eth1_data_votes: Eth1DataVotes<P>,

    /// Deposits from the deposit contract processed so far.
    pub eth1_deposit_index: u64,

    /// The validator registry.
    pub validators: Validators<P>,

    /// Actual balance of each validator.
    pub balances: Balances<P>,

    /// Randomness accumulated from randao reveals, a ring buffer indexed by epoch.
    pub randao_mixes: RandaoMixes<P>,

    /// Effective balance slashed per epoch, for the correlation penalty.
    pub slashings: Slashings<P>,

    /// Attestations included for the previous epoch, scored at its end.
    pub previous_epoch_attestations: PendingAttestations<P>,

    /// Attestations included for the current epoch so far.
    pub current_epoch_attestations: PendingAttestations<P>,

    /// Which of the last four epochs were justified, newest first.
    pub justification_bits: JustificationBits,

    /// Justified checkpoint as of the previous epoch.
    pub previous_justified_checkpoint: Checkpoint,

    /// Latest justified checkpoint.
    pub current_justified_checkpoint: Checkpoint,

    /// Latest finalized checkpoint.
    pub finalized_checkpoint: Checkpoint,
}

impl<P: Preset> Container for BeaconState<P> {
    const FIELDS: &'static [Option<usize>] = &[
        u64::FIXED_SIZE,
        Root::FIXED_SIZE,
        Slot::FIXED_SIZE,
        Fork::FIXED_SIZE,
        BeaconBlockHeader::FIXED_SIZE,
        <BlockRoots<P>>::FIXED_SIZE,
        <StateRoots<P>>::FIXED_SIZE,
        <HistoricalRoots<P>>::FIXED_SIZE,
        Eth1Data::FIXED_SIZE,
        <Eth1DataVotes<P>>::FIXED_SIZE,
        u64::FIXED_SIZE,
        <Validators<P>>::FIXED_SIZE,
        <Balances<P>>::FIXED_SIZE,
        <RandaoMixes<P>>::FIXED_SIZE,
        <Slashings<P>>::FIXED_SIZE,
        <PendingAttestations<P>>::FIXED_SIZE,
        <PendingAttestations<P>>::FIXED_SIZE,
        JustificationBits::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.genesis_time);
        visitor.field(&self.genesis_validators_root);
        visitor.field(&self.slot);
        visitor.field(&self.fork);
        visitor.field(&self.latest_block_header);
        visitor.field(&self.block_roots);
        visitor.field(&self.state_roots);
        visitor.field(&self.historical_roots);
        visitor.field(&self.eth1_data);
        visitor.field(&self.eth1_data_votes);
        visitor.field(&self.eth1_deposit_index);
        visitor.field(&self.validators);
        visitor.field(&self.balances);
        visitor.field(&self.randao_mixes);
        visitor.field(&self.slashings);
        visitor.field(&self.previous_epoch_attestations);
        visitor.field(&self.current_epoch_attestations);
        visitor.field(&self.justification_bits);
        visitor.field(&self.previous_justified_checkpoint);
        visitor.field(&self.current_justified_checkpoint);
        visitor.field(&self.finalized_checkpoint);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            genesis_time: fields.field()?,
            genesis_validators_root: fields.field()?,
            slot: fields.field()?,
            fork: fields.field()?,
            latest_block_header: fields.field()?,
            block_roots: fields.field()?,
            state_roots: fields.field()?,
            historical_roots: fields.field()?,
            eth1_data: fields.field()?,
            eth1_data_votes: fields.field()?,
            eth1_deposit_index: fields.field()?,
            validators: fields.field()?,
            balances: fields.field()?,
            randao_mixes: fields.field()?,
            slashings: fields.field()?,
            previous_epoch_attestations: fields.field()?,
            current_epoch_attestations: fields.field()?,
            justification_bits: fields.field()?,
            previous_justified_checkpoint: fields.field()?,
            current_justified_checkpoint: fields.field()?,
            finalized_checkpoint: fields.field()?,
        })
    }
}

impl<P: Preset> ForkState for BeaconState<P> {
    const FORK: ForkName = ForkName::Phase0;

    fn from_any(state: &combined::BeaconState<P>) -> Option<&Self> {
        match state {
            combined::BeaconState::Phase0(state) => Some(state),
            _ => None,
        }
    }

    fn from_any_mut(state: &mut combined::BeaconState<P>) -> Option<&mut Self> {
        match state {
            combined::BeaconState::Phase0(state) => Some(state),
            _ => None,
        }
    }

    fn into_any(self) -> combined::BeaconState<P> {
        combined::BeaconState::Phase0(self)
    }
}

impl<P: Preset> CoreState for BeaconState<P> {
    type Preset = P;

    fn fork_name(&self) -> ForkName {
        Self::FORK
    }

    fn state_root(&self) -> Root {
        self.hash_tree_root()
    }

    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }

    fn slot(&self) -> Slot {
        self.slot
    }

    fn slot_mut(&mut self) -> &mut Slot {
        &mut self.slot
    }

    fn fork(&self) -> &Fork {
        &self.fork
    }

    fn latest_block_header(&self) -> &BeaconBlockHeader {
        &self.latest_block_header
    }

    fn latest_block_header_mut(&mut self) -> &mut BeaconBlockHeader {
        &mut self.latest_block_header
    }

    fn block_roots(&self) -> &BlockRoots<P> {
        &self.block_roots
    }

    fn block_roots_mut(&mut self) -> &mut BlockRoots<P> {
        &mut self.block_roots
    }

    fn state_roots(&self) -> &StateRoots<P> {
        &self.state_roots
    }

    fn state_roots_mut(&mut self) -> &mut StateRoots<P> {
        &mut self.state_roots
    }

    fn historical_roots(&self) -> &HistoricalRoots<P> {
        &self.historical_roots
    }

    fn historical_roots_mut(&mut self) -> &mut HistoricalRoots<P> {
        &mut self.historical_roots
    }

    fn eth1_data(&self) -> &Eth1Data {
        &self.eth1_data
    }

    fn eth1_data_mut(&mut self) -> &mut Eth1Data {
        &mut self.eth1_data
    }

    fn eth1_data_votes(&self) -> &Eth1DataVotes<P> {
        &self.eth1_data_votes
    }

    fn eth1_data_votes_mut(&mut self) -> &mut Eth1DataVotes<P> {
        &mut self.eth1_data_votes
    }

    fn eth1_deposit_index(&self) -> u64 {
        self.eth1_deposit_index
    }

    fn eth1_deposit_index_mut(&mut self) -> &mut u64 {
        &mut self.eth1_deposit_index
    }

    fn validators(&self) -> &[Validator] {
        &self.validators
    }

    fn validators_mut(&mut self) -> &mut [Validator] {
        &mut self.validators
    }

    fn balances(&self) -> &[Gwei] {
        &self.balances
    }

    fn balances_mut(&mut self) -> &mut [Gwei] {
        &mut self.balances
    }

    fn push_validator(&mut self, validator: Validator, balance: Gwei) -> Result<(), CapacityError> {
        self.validators.push(validator)?;
        // Invariant: balances share the registry's length and limit, so they have room too.
        self.balances.push(balance)
    }

    fn randao_mixes(&self) -> &RandaoMixes<P> {
        &self.randao_mixes
    }

    fn randao_mixes_mut(&mut self) -> &mut RandaoMixes<P> {
        &mut self.randao_mixes
    }

    fn slashings(&self) -> &Slashings<P> {
        &self.slashings
    }

    fn slashings_mut(&mut self) -> &mut Slashings<P> {
        &mut self.slashings
    }

    fn justification_bits(&self) -> &JustificationBits {
        &self.justification_bits
    }

    fn justification_bits_mut(&mut self) -> &mut JustificationBits {
        &mut self.justification_bits
    }

    fn previous_justified_checkpoint(&self) -> Checkpoint {
        self.previous_justified_checkpoint
    }

    fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.previous_justified_checkpoint
    }

    fn current_justified_checkpoint(&self) -> Checkpoint {
        self.current_justified_checkpoint
    }

    fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.current_justified_checkpoint
    }

    fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.finalized_checkpoint
    }
}
