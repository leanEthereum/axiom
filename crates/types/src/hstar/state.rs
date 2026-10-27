//! The beacon state of Hstar: Gloas's, with the post-quantum key registry.
//!
//! The registry is a list parallel to the validators, so the validator record keeps its shape.
//! See EIP-8450.

use axiom_ssz::{
    CapacityError, Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, Sequence,
    SequenceMut, Ssz,
};

use crate::{
    BuilderIndex, Epoch, ForkName, Gwei, Hash32, ParticipationFlags, Preset, Root, Slot,
    ValidatorIndex, WithdrawalIndex,
    accessors::{
        BuilderState, CoreState, ForkState, LookaheadState, ParticipationState, PendingQueueState,
        PqRegistryState, SyncCommitteeState, WithdrawalState,
    },
    combined,
    hstar::{
        Balances, BeaconBlockHeader, BlockRoots, BuilderPendingPayments, BuilderPendingWithdrawals,
        Builders, Checkpoint, EpochParticipation, Eth1Data, Eth1DataVotes,
        ExecutionPayloadAvailability, ExecutionPayloadBid, Fork, HistoricalRoots,
        HistoricalSummaries, InactivityScores, JustificationBits, PayloadTimelinessCommitteeWindow,
        PendingConsolidation, PendingConsolidations, PendingDeposit, PendingDeposits,
        PendingPartialWithdrawal, PendingPartialWithdrawals, PendingPqKeyAuthorization,
        PendingPqKeyAuthorizations, PqPublicKeys, ProposerLookahead, RandaoMixes, Slashings,
        StateRoots, SyncCommittee, Validator, ValidatorPqPublicKeys, Validators, Withdrawals,
    },
};

/// The full consensus state at one slot.
///
/// Every block and epoch transition is a pure function from one state to the next.
/// See the Gloas beacon chain spec and EIP-8450.
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
    pub validators: Validators,

    /// Actual balance of each validator.
    pub balances: Balances,

    /// Randomness accumulated from randao reveals, a ring buffer indexed by epoch.
    pub randao_mixes: RandaoMixes<P>,

    /// Effective balance slashed per epoch, for the correlation penalty.
    pub slashings: Slashings<P>,

    /// Duties each validator fulfilled in the previous epoch.
    pub previous_epoch_participation: EpochParticipation,

    /// Duties each validator fulfilled in the current epoch.
    pub current_epoch_participation: EpochParticipation,

    /// Which of the last four epochs were justified, newest first.
    pub justification_bits: JustificationBits,

    /// Justified checkpoint as of the previous epoch.
    pub previous_justified_checkpoint: Checkpoint,

    /// Latest justified checkpoint.
    pub current_justified_checkpoint: Checkpoint,

    /// Latest finalized checkpoint.
    pub finalized_checkpoint: Checkpoint,

    /// Per-validator inactivity scores, which drive the inactivity leak.
    pub inactivity_scores: InactivityScores,

    /// Sync committee of the current period.
    pub current_sync_committee: SyncCommittee<P>,

    /// Sync committee of the next period.
    pub next_sync_committee: SyncCommittee<P>,

    /// Hash of the latest execution block whose payload the chain accepted.
    pub latest_block_hash: Hash32,

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
    pub pending_deposits: PendingDeposits,

    /// Partial withdrawals waiting for their epoch.
    pub pending_partial_withdrawals: PendingPartialWithdrawals,

    /// Consolidations waiting for their source to be withdrawable.
    pub pending_consolidations: PendingConsolidations,

    /// Proposers of the current and next epochs, fixed one epoch ahead.
    pub proposer_lookahead: ProposerLookahead<P>,

    /// The builder registry.
    pub builders: Builders,

    /// Builder the next withdrawal sweep starts at.
    pub next_withdrawal_builder_index: BuilderIndex,

    /// Whether each recent slot's payload arrived, a ring buffer indexed by slot.
    pub execution_payload_availability: ExecutionPayloadAvailability<P>,

    /// Payments owed to builders for the previous and current epochs' bids.
    pub builder_pending_payments: BuilderPendingPayments<P>,

    /// Builder payments waiting to be withdrawn.
    pub builder_pending_withdrawals: BuilderPendingWithdrawals,

    /// The bid of the latest block, which its payload must honour.
    pub latest_execution_payload_bid: ExecutionPayloadBid,

    /// Withdrawals the next payload must carry, fixed when its block is processed.
    pub payload_expected_withdrawals: Withdrawals,

    /// Payload timeliness committees of the previous, current, and next epochs.
    pub ptc_window: PayloadTimelinessCommitteeWindow<P>,

    /// Registered post-quantum keys, one entry per validator, by validator index.
    pub pq_public_keys: ValidatorPqPublicKeys,

    /// Key authorizations by withdrawal addresses, waiting for a matching registration.
    pub pending_pq_key_authorizations: PendingPqKeyAuthorizations,
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
        Validators::FIXED_SIZE,
        Balances::FIXED_SIZE,
        <RandaoMixes<P>>::FIXED_SIZE,
        <Slashings<P>>::FIXED_SIZE,
        EpochParticipation::FIXED_SIZE,
        EpochParticipation::FIXED_SIZE,
        JustificationBits::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        Checkpoint::FIXED_SIZE,
        InactivityScores::FIXED_SIZE,
        <SyncCommittee<P>>::FIXED_SIZE,
        <SyncCommittee<P>>::FIXED_SIZE,
        Hash32::FIXED_SIZE,
        WithdrawalIndex::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
        <HistoricalSummaries<P>>::FIXED_SIZE,
        u64::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        PendingDeposits::FIXED_SIZE,
        PendingPartialWithdrawals::FIXED_SIZE,
        PendingConsolidations::FIXED_SIZE,
        <ProposerLookahead<P>>::FIXED_SIZE,
        Builders::FIXED_SIZE,
        BuilderIndex::FIXED_SIZE,
        <ExecutionPayloadAvailability<P>>::FIXED_SIZE,
        <BuilderPendingPayments<P>>::FIXED_SIZE,
        BuilderPendingWithdrawals::FIXED_SIZE,
        ExecutionPayloadBid::FIXED_SIZE,
        Withdrawals::FIXED_SIZE,
        <PayloadTimelinessCommitteeWindow<P>>::FIXED_SIZE,
        ValidatorPqPublicKeys::FIXED_SIZE,
        PendingPqKeyAuthorizations::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 48]);

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
        visitor.field(&self.latest_block_hash);
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
        visitor.field(&self.builders);
        visitor.field(&self.next_withdrawal_builder_index);
        visitor.field(&self.execution_payload_availability);
        visitor.field(&self.builder_pending_payments);
        visitor.field(&self.builder_pending_withdrawals);
        visitor.field(&self.latest_execution_payload_bid);
        visitor.field(&self.payload_expected_withdrawals);
        visitor.field(&self.ptc_window);
        visitor.field(&self.pq_public_keys);
        visitor.field(&self.pending_pq_key_authorizations);
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
            latest_block_hash: fields.field()?,
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
            builders: fields.field()?,
            next_withdrawal_builder_index: fields.field()?,
            execution_payload_availability: fields.field()?,
            builder_pending_payments: fields.field()?,
            builder_pending_withdrawals: fields.field()?,
            latest_execution_payload_bid: fields.field()?,
            payload_expected_withdrawals: fields.field()?,
            ptc_window: fields.field()?,
            pq_public_keys: fields.field()?,
            pending_pq_key_authorizations: fields.field()?,
        })
    }
}

impl<P: Preset> ForkState for BeaconState<P> {
    const FORK: ForkName = ForkName::Hstar;

    fn from_any(state: &combined::BeaconState<P>) -> Option<&Self> {
        match state {
            combined::BeaconState::Hstar(state) => Some(state),
            _ => None,
        }
    }

    fn from_any_mut(state: &mut combined::BeaconState<P>) -> Option<&mut Self> {
        match state {
            combined::BeaconState::Hstar(state) => Some(state),
            _ => None,
        }
    }

    fn into_any(self) -> combined::BeaconState<P> {
        combined::BeaconState::Hstar(self)
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

    fn validators(&self) -> &Sequence<Validator> {
        &self.validators
    }

    fn validators_mut(&mut self) -> SequenceMut<'_, Validator> {
        self.validators.elements_mut()
    }

    fn balances(&self) -> &Sequence<Gwei> {
        &self.balances
    }

    fn balances_mut(&mut self) -> SequenceMut<'_, Gwei> {
        self.balances.elements_mut()
    }

    fn push_validator(&mut self, validator: Validator, balance: Gwei) -> Result<(), CapacityError> {
        // Progressive lists have no limit, so the registry always grows.
        self.validators.push(validator);
        self.balances.push(balance);

        // Invariant: the key registry has one entry per validator.
        // A new validator starts with the all-zero entry, which has no key.
        // See the modified add_validator_to_registry in EIP-8450.
        self.pq_public_keys.push(PqPublicKeys::default());
        Ok(())
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
    fn previous_epoch_participation(&self) -> &Sequence<ParticipationFlags> {
        &self.previous_epoch_participation
    }

    fn current_epoch_participation(&self) -> &Sequence<ParticipationFlags> {
        &self.current_epoch_participation
    }

    fn epoch_participation_mut(
        &mut self,
    ) -> (
        SequenceMut<'_, ParticipationFlags>,
        SequenceMut<'_, ParticipationFlags>,
    ) {
        (
            self.previous_epoch_participation.elements_mut(),
            self.current_epoch_participation.elements_mut(),
        )
    }

    fn inactivity_scores(&self) -> &Sequence<u64> {
        &self.inactivity_scores
    }

    fn inactivity_scores_mut(&mut self) -> SequenceMut<'_, u64> {
        self.inactivity_scores.elements_mut()
    }

    fn push_participant(&mut self) -> Result<(), CapacityError> {
        // Progressive lists have no limit, so every list always grows.
        self.previous_epoch_participation
            .push(ParticipationFlags::default());
        self.current_epoch_participation
            .push(ParticipationFlags::default());
        self.inactivity_scores.push(0);
        Ok(())
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

    fn pending_deposits(&self) -> &Sequence<PendingDeposit> {
        &self.pending_deposits
    }

    fn push_pending_deposit(&mut self, deposit: PendingDeposit) -> Result<(), CapacityError> {
        self.pending_deposits.push(deposit);
        Ok(())
    }

    fn remove_pending_deposits(&mut self, count: usize) {
        self.pending_deposits.drain(..count);
    }

    fn pending_partial_withdrawals(&self) -> &Sequence<PendingPartialWithdrawal> {
        &self.pending_partial_withdrawals
    }

    fn push_pending_partial_withdrawal(
        &mut self,
        withdrawal: PendingPartialWithdrawal,
    ) -> Result<(), CapacityError> {
        self.pending_partial_withdrawals.push(withdrawal);
        Ok(())
    }

    fn remove_pending_partial_withdrawals(&mut self, count: usize) {
        self.pending_partial_withdrawals.drain(..count);
    }

    fn pending_consolidations(&self) -> &Sequence<PendingConsolidation> {
        &self.pending_consolidations
    }

    fn push_pending_consolidation(
        &mut self,
        consolidation: PendingConsolidation,
    ) -> Result<(), CapacityError> {
        self.pending_consolidations.push(consolidation);
        Ok(())
    }

    fn remove_pending_consolidations(&mut self, count: usize) {
        self.pending_consolidations.drain(..count);
    }
}

impl<P: Preset> LookaheadState for BeaconState<P> {
    fn proposer_lookahead(&self) -> &ProposerLookahead<P> {
        &self.proposer_lookahead
    }

    fn proposer_lookahead_mut(&mut self) -> &mut ProposerLookahead<P> {
        &mut self.proposer_lookahead
    }
}

impl<P: Preset> BuilderState for BeaconState<P> {
    fn latest_block_hash(&self) -> Hash32 {
        self.latest_block_hash
    }

    fn latest_block_hash_mut(&mut self) -> &mut Hash32 {
        &mut self.latest_block_hash
    }

    fn builders(&self) -> &Builders {
        &self.builders
    }

    fn builders_mut(&mut self) -> &mut Builders {
        &mut self.builders
    }

    fn next_withdrawal_builder_index(&self) -> BuilderIndex {
        self.next_withdrawal_builder_index
    }

    fn next_withdrawal_builder_index_mut(&mut self) -> &mut BuilderIndex {
        &mut self.next_withdrawal_builder_index
    }

    fn execution_payload_availability(&self) -> &ExecutionPayloadAvailability<P> {
        &self.execution_payload_availability
    }

    fn execution_payload_availability_mut(&mut self) -> &mut ExecutionPayloadAvailability<P> {
        &mut self.execution_payload_availability
    }

    fn builder_pending_payments(&self) -> &BuilderPendingPayments<P> {
        &self.builder_pending_payments
    }

    fn builder_pending_payments_mut(&mut self) -> &mut BuilderPendingPayments<P> {
        &mut self.builder_pending_payments
    }

    fn builder_pending_withdrawals(&self) -> &BuilderPendingWithdrawals {
        &self.builder_pending_withdrawals
    }

    fn builder_pending_withdrawals_mut(&mut self) -> &mut BuilderPendingWithdrawals {
        &mut self.builder_pending_withdrawals
    }

    fn latest_execution_payload_bid(&self) -> &ExecutionPayloadBid {
        &self.latest_execution_payload_bid
    }

    fn latest_execution_payload_bid_mut(&mut self) -> &mut ExecutionPayloadBid {
        &mut self.latest_execution_payload_bid
    }

    fn payload_expected_withdrawals(&self) -> &Withdrawals {
        &self.payload_expected_withdrawals
    }

    fn payload_expected_withdrawals_mut(&mut self) -> &mut Withdrawals {
        &mut self.payload_expected_withdrawals
    }

    fn ptc_window(&self) -> &PayloadTimelinessCommitteeWindow<P> {
        &self.ptc_window
    }

    fn ptc_window_mut(&mut self) -> &mut PayloadTimelinessCommitteeWindow<P> {
        &mut self.ptc_window
    }
}

impl<P: Preset> PqRegistryState for BeaconState<P> {
    fn pq_public_keys(&self) -> &Sequence<PqPublicKeys> {
        &self.pq_public_keys
    }

    fn pq_public_keys_mut(&mut self) -> SequenceMut<'_, PqPublicKeys> {
        self.pq_public_keys.elements_mut()
    }

    fn pending_pq_key_authorizations(&self) -> &Sequence<PendingPqKeyAuthorization> {
        &self.pending_pq_key_authorizations
    }

    fn pending_pq_key_authorizations_mut(&mut self) -> &mut PendingPqKeyAuthorizations {
        &mut self.pending_pq_key_authorizations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Minimal, XmssPublicKey, constants::PQ_KEYS_VERSION_1};

    #[test]
    fn the_key_registry_grows_with_the_validators() {
        // Invariant: one key entry per validator, so the two lists never disagree.
        //
        // Fixture state: an empty Hstar registry.
        let mut state = BeaconState::<Minimal>::default();

        // Two validators join, each with 32 ETH.
        for _ in 0..2 {
            state
                .push_validator(Validator::default(), Gwei(32_000_000_000))
                .unwrap();
        }

        // Each one holds the all-zero entry, which has no key.
        assert_eq!(state.validators().len(), 2);
        assert_eq!(
            state.pq_public_keys().to_vec(),
            [PqPublicKeys::default(), PqPublicKeys::default()]
        );
    }

    #[test]
    fn a_registered_key_is_visible_by_index() {
        // Fixture state: two validators, neither registered.
        let mut state = BeaconState::<Minimal>::default();
        for _ in 0..2 {
            state
                .push_validator(Validator::default(), Gwei(32_000_000_000))
                .unwrap();
        }
        let keys = PqPublicKeys {
            version: PQ_KEYS_VERSION_1,
            xmss_public_key: XmssPublicKey([5; 32]),
        };

        // Validator 1 registers; validator 0 keeps the unset entry.
        *state.pq_public_keys_mut().get_mut(1).unwrap() = keys;

        assert_eq!(
            state.pq_public_keys().to_vec(),
            [PqPublicKeys::default(), keys]
        );
        assert!(!state.is_pq_registered(ValidatorIndex(0)));
        assert!(state.is_pq_registered(ValidatorIndex(1)));
    }
}
