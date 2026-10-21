//! The beacon state of the Fulu fork.

use axiom_ssz::{
    BitVector, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, Vector,
};

use crate::{
    BeaconBlockHeader, Bytes32, Checkpoint, Epoch, Eth1Data, ExecutionPayloadHeader, Fork, Gwei,
    HistoricalSummary, ParticipationFlags, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, Preset, Root, Slot, SyncCommittee, Validator, ValidatorIndex,
    WithdrawalIndex, constants::JUSTIFICATION_BITS_LENGTH,
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

/// Participation flags per validator.
pub type EpochParticipation<P> = List<ParticipationFlags, <P as Preset>::ValidatorRegistryLimit>;

/// Inactivity scores per validator.
pub type InactivityScores<P> = List<u64, <P as Preset>::ValidatorRegistryLimit>;

/// Summaries of past root periods.
pub type HistoricalSummaries<P> = List<HistoricalSummary, <P as Preset>::HistoricalRootsLimit>;

/// The pending deposit queue.
pub type PendingDeposits<P> = List<PendingDeposit, <P as Preset>::PendingDepositsLimit>;

/// The pending partial withdrawal queue.
pub type PendingPartialWithdrawals<P> =
    List<PendingPartialWithdrawal, <P as Preset>::PendingPartialWithdrawalsLimit>;

/// The pending consolidation queue.
pub type PendingConsolidations<P> =
    List<PendingConsolidation, <P as Preset>::PendingConsolidationsLimit>;

/// Proposers of the current and next epochs, see EIP-7917.
pub type ProposerLookahead<P> = Vector<ValidatorIndex, <P as Preset>::ProposerLookaheadSlots>;

/// Justification history of the last four epochs.
pub type JustificationBits = BitVector<Const<JUSTIFICATION_BITS_LENGTH>>;

/// The full consensus state at one slot.
///
/// Every block and epoch transition is a pure function from one state to the next.
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

    /// Duties each validator fulfilled in the previous epoch.
    pub previous_epoch_participation: EpochParticipation<P>,

    /// Duties each validator fulfilled in the current epoch.
    pub current_epoch_participation: EpochParticipation<P>,

    /// Which of the last four epochs were justified, newest first.
    pub justification_bits: JustificationBits,

    /// Justified checkpoint as of the previous epoch.
    pub previous_justified_checkpoint: Checkpoint,

    /// Latest justified checkpoint.
    pub current_justified_checkpoint: Checkpoint,

    /// Latest finalized checkpoint.
    pub finalized_checkpoint: Checkpoint,

    /// Per-validator inactivity scores, which drive the inactivity leak.
    pub inactivity_scores: InactivityScores<P>,

    /// Sync committee of the current period.
    pub current_sync_committee: SyncCommittee<P>,

    /// Sync committee of the next period.
    pub next_sync_committee: SyncCommittee<P>,

    /// Header of the latest execution payload.
    pub latest_execution_payload_header: ExecutionPayloadHeader<P>,

    /// Index the next withdrawal will get.
    pub next_withdrawal_index: WithdrawalIndex,

    /// Validator the next withdrawal sweep starts at.
    pub next_withdrawal_validator_index: ValidatorIndex,

    /// Summaries of every full period of block and state roots.
    pub historical_summaries: HistoricalSummaries<P>,

    /// Deposit contract index of the first deposit request, see EIP-6110.
    pub deposit_requests_start_index: u64,

    /// Deposit churn carried over from the previous epoch.
    pub deposit_balance_to_consume: Gwei,

    /// Exit churn left in the latest exit epoch.
    pub exit_balance_to_consume: Gwei,

    /// Earliest epoch a new exit can be scheduled for.
    pub earliest_exit_epoch: Epoch,

    /// Consolidation churn left in the latest consolidation epoch.
    pub consolidation_balance_to_consume: Gwei,

    /// Earliest epoch a new consolidation can be scheduled for.
    pub earliest_consolidation_epoch: Epoch,

    /// Deposits waiting for churn.
    pub pending_deposits: PendingDeposits<P>,

    /// Partial withdrawals waiting for their epoch.
    pub pending_partial_withdrawals: PendingPartialWithdrawals<P>,

    /// Consolidations waiting for their source to be withdrawable.
    pub pending_consolidations: PendingConsolidations<P>,

    /// Proposers of the current and next epochs, fixed one epoch ahead.
    pub proposer_lookahead: ProposerLookahead<P>,
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
        <EpochParticipation<P>>::FIXED_SIZE,
        <EpochParticipation<P>>::FIXED_SIZE,
        JustificationBits::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        <InactivityScores<P>>::FIXED_SIZE,
        <SyncCommittee<P>>::FIXED_SIZE,
        <SyncCommittee<P>>::FIXED_SIZE,
        <ExecutionPayloadHeader<P>>::FIXED_SIZE,
        WithdrawalIndex::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        <HistoricalSummaries<P>>::FIXED_SIZE,
        u64::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        <PendingDeposits<P>>::FIXED_SIZE,
        <PendingPartialWithdrawals<P>>::FIXED_SIZE,
        <PendingConsolidations<P>>::FIXED_SIZE,
        <ProposerLookahead<P>>::FIXED_SIZE,
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
        visitor.field(&self.previous_epoch_participation);
        visitor.field(&self.current_epoch_participation);
        visitor.field(&self.justification_bits);
        visitor.field(&self.previous_justified_checkpoint);
        visitor.field(&self.current_justified_checkpoint);
        visitor.field(&self.finalized_checkpoint);
        visitor.field(&self.inactivity_scores);
        visitor.field(&self.current_sync_committee);
        visitor.field(&self.next_sync_committee);
        visitor.field(&self.latest_execution_payload_header);
        visitor.field(&self.next_withdrawal_index);
        visitor.field(&self.next_withdrawal_validator_index);
        visitor.field(&self.historical_summaries);
        visitor.field(&self.deposit_requests_start_index);
        visitor.field(&self.deposit_balance_to_consume);
        visitor.field(&self.exit_balance_to_consume);
        visitor.field(&self.earliest_exit_epoch);
        visitor.field(&self.consolidation_balance_to_consume);
        visitor.field(&self.earliest_consolidation_epoch);
        visitor.field(&self.pending_deposits);
        visitor.field(&self.pending_partial_withdrawals);
        visitor.field(&self.pending_consolidations);
        visitor.field(&self.proposer_lookahead);
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
            previous_epoch_participation: fields.field()?,
            current_epoch_participation: fields.field()?,
            justification_bits: fields.field()?,
            previous_justified_checkpoint: fields.field()?,
            current_justified_checkpoint: fields.field()?,
            finalized_checkpoint: fields.field()?,
            inactivity_scores: fields.field()?,
            current_sync_committee: fields.field()?,
            next_sync_committee: fields.field()?,
            latest_execution_payload_header: fields.field()?,
            next_withdrawal_index: fields.field()?,
            next_withdrawal_validator_index: fields.field()?,
            historical_summaries: fields.field()?,
            deposit_requests_start_index: fields.field()?,
            deposit_balance_to_consume: fields.field()?,
            exit_balance_to_consume: fields.field()?,
            earliest_exit_epoch: fields.field()?,
            consolidation_balance_to_consume: fields.field()?,
            earliest_consolidation_epoch: fields.field()?,
            pending_deposits: fields.field()?,
            pending_partial_withdrawals: fields.field()?,
            pending_consolidations: fields.field()?,
            proposer_lookahead: fields.field()?,
        })
    }
}
