//! The beacon state of phase0.

use axiom_ssz::{
    BitVector, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, Vector,
};

use crate::{
    Bytes32, Gwei, Preset, Root, Slot,
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
