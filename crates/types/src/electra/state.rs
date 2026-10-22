//! The beacon state of Electra, with pending queues and balance churn.

use axiom_ssz::{CapacityError, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    Epoch, ForkName, Gwei, ParticipationFlags, Preset, Root, Slot, ValidatorIndex, WithdrawalIndex,
    accessors::{
        CoreState, ExecutionHeaderState, ForkState, ParticipationState, PendingQueueState,
        SyncCommitteeState, WithdrawalState,
    },
    combined,
    electra::{
        Balances, BeaconBlockHeader, BlockRoots, Checkpoint, EpochParticipation, Eth1Data,
        Eth1DataVotes, ExecutionPayloadHeader, Fork, HistoricalRoots, HistoricalSummaries,
        InactivityScores, JustificationBits, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, RandaoMixes, Slashings, StateRoots, SyncCommittee, Validator,
        Validators,
    },
};

/// The pending deposit queue.
pub type PendingDeposits<P> = List<PendingDeposit, <P as Preset>::PendingDepositsLimit>;

/// The pending partial withdrawal queue.
pub type PendingPartialWithdrawals<P> =
    List<PendingPartialWithdrawal, <P as Preset>::PendingPartialWithdrawalsLimit>;

/// The pending consolidation queue.
pub type PendingConsolidations<P> =
    List<PendingConsolidation, <P as Preset>::PendingConsolidationsLimit>;

/// The full consensus state at one slot.
///
/// Every block and epoch transition is a pure function from one state to the next.
/// See the Electra beacon chain spec.
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
        })
    }
}

impl<P: Preset> ForkState for BeaconState<P> {
    const FORK: ForkName = ForkName::Electra;

    fn from_any(state: &combined::BeaconState<P>) -> Option<&Self> {
        match state {
            combined::BeaconState::Electra(state) => Some(state),
            _ => None,
        }
    }

    fn from_any_mut(state: &mut combined::BeaconState<P>) -> Option<&mut Self> {
        match state {
            combined::BeaconState::Electra(state) => Some(state),
            _ => None,
        }
    }

    fn into_any(self) -> combined::BeaconState<P> {
        combined::BeaconState::Electra(self)
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

impl<P: Preset> ParticipationState for BeaconState<P> {
    fn previous_epoch_participation(&self) -> &[ParticipationFlags] {
        &self.previous_epoch_participation
    }

    fn current_epoch_participation(&self) -> &[ParticipationFlags] {
        &self.current_epoch_participation
    }

    fn epoch_participation_mut(
        &mut self,
    ) -> (&mut [ParticipationFlags], &mut [ParticipationFlags]) {
        (
            &mut self.previous_epoch_participation[..],
            &mut self.current_epoch_participation[..],
        )
    }

    fn inactivity_scores(&self) -> &[u64] {
        &self.inactivity_scores
    }

    fn inactivity_scores_mut(&mut self) -> &mut [u64] {
        &mut self.inactivity_scores
    }

    fn push_participant(&mut self) -> Result<(), CapacityError> {
        self.previous_epoch_participation
            .push(ParticipationFlags::default())?;
        self.current_epoch_participation
            .push(ParticipationFlags::default())?;
        self.inactivity_scores.push(0)
    }
}

impl<P: Preset> SyncCommitteeState for BeaconState<P> {
    fn current_sync_committee(&self) -> &SyncCommittee<P> {
        &self.current_sync_committee
    }

    fn current_sync_committee_mut(&mut self) -> &mut SyncCommittee<P> {
        &mut self.current_sync_committee
    }

    fn next_sync_committee(&self) -> &SyncCommittee<P> {
        &self.next_sync_committee
    }

    fn next_sync_committee_mut(&mut self) -> &mut SyncCommittee<P> {
        &mut self.next_sync_committee
    }
}

impl<P: Preset> ExecutionHeaderState for BeaconState<P> {
    type ExecutionPayloadHeader = ExecutionPayloadHeader<P>;

    fn latest_execution_payload_header(&self) -> &ExecutionPayloadHeader<P> {
        &self.latest_execution_payload_header
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut ExecutionPayloadHeader<P> {
        &mut self.latest_execution_payload_header
    }
}

impl<P: Preset> WithdrawalState for BeaconState<P> {
    fn next_withdrawal_index(&self) -> WithdrawalIndex {
        self.next_withdrawal_index
    }

    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex {
        &mut self.next_withdrawal_index
    }

    fn next_withdrawal_validator_index(&self) -> ValidatorIndex {
        self.next_withdrawal_validator_index
    }

    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex {
        &mut self.next_withdrawal_validator_index
    }

    fn historical_summaries(&self) -> &HistoricalSummaries<P> {
        &self.historical_summaries
    }

    fn historical_summaries_mut(&mut self) -> &mut HistoricalSummaries<P> {
        &mut self.historical_summaries
    }
}

impl<P: Preset> PendingQueueState for BeaconState<P> {
    fn deposit_requests_start_index(&self) -> u64 {
        self.deposit_requests_start_index
    }

    fn deposit_requests_start_index_mut(&mut self) -> &mut u64 {
        &mut self.deposit_requests_start_index
    }

    fn deposit_balance_to_consume(&self) -> Gwei {
        self.deposit_balance_to_consume
    }

    fn deposit_balance_to_consume_mut(&mut self) -> &mut Gwei {
        &mut self.deposit_balance_to_consume
    }

    fn exit_balance_to_consume(&self) -> Gwei {
        self.exit_balance_to_consume
    }

    fn exit_balance_to_consume_mut(&mut self) -> &mut Gwei {
        &mut self.exit_balance_to_consume
    }

    fn earliest_exit_epoch(&self) -> Epoch {
        self.earliest_exit_epoch
    }

    fn earliest_exit_epoch_mut(&mut self) -> &mut Epoch {
        &mut self.earliest_exit_epoch
    }

    fn consolidation_balance_to_consume(&self) -> Gwei {
        self.consolidation_balance_to_consume
    }

    fn consolidation_balance_to_consume_mut(&mut self) -> &mut Gwei {
        &mut self.consolidation_balance_to_consume
    }

    fn earliest_consolidation_epoch(&self) -> Epoch {
        self.earliest_consolidation_epoch
    }

    fn earliest_consolidation_epoch_mut(&mut self) -> &mut Epoch {
        &mut self.earliest_consolidation_epoch
    }

    fn pending_deposits(&self) -> &[PendingDeposit] {
        &self.pending_deposits
    }

    fn push_pending_deposit(&mut self, deposit: PendingDeposit) -> Result<(), CapacityError> {
        self.pending_deposits.push(deposit)
    }

    fn remove_pending_deposits(&mut self, count: usize) {
        self.pending_deposits.drain(..count);
    }

    fn pending_partial_withdrawals(&self) -> &[PendingPartialWithdrawal] {
        &self.pending_partial_withdrawals
    }

    fn push_pending_partial_withdrawal(
        &mut self,
        withdrawal: PendingPartialWithdrawal,
    ) -> Result<(), CapacityError> {
        self.pending_partial_withdrawals.push(withdrawal)
    }

    fn remove_pending_partial_withdrawals(&mut self, count: usize) {
        self.pending_partial_withdrawals.drain(..count);
    }

    fn pending_consolidations(&self) -> &[PendingConsolidation] {
        &self.pending_consolidations
    }

    fn push_pending_consolidation(
        &mut self,
        consolidation: PendingConsolidation,
    ) -> Result<(), CapacityError> {
        self.pending_consolidations.push(consolidation)
    }

    fn remove_pending_consolidations(&mut self, count: usize) {
        self.pending_consolidations.drain(..count);
    }
}
