//! The beacon state of the Fulu fork.

use axiom_ssz::{
    BitVector, Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, Vector,
};

use crate::{
    BeaconBlockHeader, BlsPubkey, Bytes32, Checkpoint, Domain, DomainType, Epoch, Eth1Data,
    ExecutionPayloadHeader, Fork, Gwei, HistoricalSummary, ParticipationFlags,
    PendingConsolidation, PendingDeposit, PendingPartialWithdrawal, Preset, Root, Slot,
    SyncCommittee, Validator, ValidatorIndex, WithdrawalIndex,
    constants::JUSTIFICATION_BITS_LENGTH,
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

impl<P: Preset> BeaconState<P> {
    /// Epoch of the state's slot.
    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.slot.epoch::<P>()
    }

    /// Epoch before the current one, or genesis at genesis.
    #[must_use]
    pub const fn previous_epoch(&self) -> Epoch {
        self.current_epoch().saturating_sub(1)
    }

    /// Root of the block at a recent slot.
    ///
    /// Returns nothing unless the slot is in the past and still in the ring buffer.
    /// See `get_block_root_at_slot` in the phase0 beacon chain spec.
    #[must_use]
    pub fn block_root_at_slot(&self, slot: Slot) -> Option<Root> {
        let in_range =
            slot < self.slot && self.slot.0 <= slot.0.saturating_add(P::SLOTS_PER_HISTORICAL_ROOT);
        in_range.then(|| self.block_roots[(slot % P::SLOTS_PER_HISTORICAL_ROOT) as usize])
    }

    /// Root of the block at the start of a recent epoch.
    #[must_use]
    pub fn block_root(&self, epoch: Epoch) -> Option<Root> {
        self.block_root_at_slot(epoch.start_slot::<P>())
    }

    /// Randao mix of a recent epoch.
    #[must_use]
    pub fn randao_mix(&self, epoch: Epoch) -> Bytes32 {
        self.randao_mixes[(epoch % P::EPOCHS_PER_HISTORICAL_VECTOR) as usize]
    }

    /// Indices of the validators active at an epoch, in registry order.
    #[must_use]
    pub fn active_validator_indices(&self, epoch: Epoch) -> Vec<ValidatorIndex> {
        self.validators
            .iter()
            .enumerate()
            .filter(|(_, validator)| validator.is_active_at(epoch))
            .map(|(index, _)| ValidatorIndex::from(index))
            .collect()
    }

    /// Seed for a domain at an epoch.
    ///
    /// The mix comes from MIN_SEED_LOOKAHEAD + 1 epochs earlier.
    /// That mix was fixed before anyone could know which seed it would feed.
    /// See `get_seed` in the phase0 beacon chain spec.
    #[must_use]
    pub fn seed(&self, epoch: Epoch, domain_type: DomainType) -> Bytes32 {
        // Adding the vector length first keeps the subtraction from underflowing near genesis.
        let mix_epoch =
            Epoch(epoch.0 + P::EPOCHS_PER_HISTORICAL_VECTOR - P::MIN_SEED_LOOKAHEAD - 1);
        let mix = self.randao_mix(mix_epoch);

        let mut preimage = [0; 4 + 8 + 32];
        preimage[..4].copy_from_slice(&domain_type.0);
        preimage[4..12].copy_from_slice(&epoch.0.to_le_bytes());
        preimage[12..].copy_from_slice(&mix.0);
        Bytes32(Root::sha256(&preimage).0)
    }

    /// Committees per slot at an epoch, between 1 and the preset maximum.
    ///
    /// See `get_committee_count_per_slot` in the phase0 beacon chain spec.
    #[must_use]
    pub fn committee_count_per_slot(&self, active_validator_count: usize) -> u64 {
        (active_validator_count as u64 / P::SLOTS_PER_EPOCH / P::TARGET_COMMITTEE_SIZE)
            .clamp(1, P::MAX_COMMITTEES_PER_SLOT)
    }

    /// Sum of the effective balances of some validators, at least one increment.
    ///
    /// The floor keeps every division by a total balance well defined.
    #[must_use]
    pub fn total_balance(&self, indices: impl IntoIterator<Item = ValidatorIndex>) -> Gwei {
        let sum: Gwei = indices
            .into_iter()
            .map(|index| self.validators[index.as_usize()].effective_balance)
            .sum();
        sum.max(P::EFFECTIVE_BALANCE_INCREMENT)
    }

    /// Sum of the effective balances of the validators active in the current epoch.
    #[must_use]
    pub fn total_active_balance(&self) -> Gwei {
        let epoch = self.current_epoch();
        let sum: Gwei = self
            .validators
            .iter()
            .filter(|validator| validator.is_active_at(epoch))
            .map(|validator| validator.effective_balance)
            .sum();
        sum.max(P::EFFECTIVE_BALANCE_INCREMENT)
    }

    /// Signature domain of a message type at an epoch.
    ///
    /// Messages from before the latest fork sign with the previous fork version.
    /// See `get_domain` in the phase0 beacon chain spec.
    #[must_use]
    pub fn domain(&self, domain_type: DomainType, epoch: Epoch) -> Domain {
        Domain::compute(
            domain_type,
            self.fork.version_at(epoch),
            self.genesis_validators_root,
        )
    }

    /// Proposer of the current slot, read from the lookahead.
    ///
    /// See `get_beacon_proposer_index` in the Fulu beacon chain spec.
    #[must_use]
    pub fn beacon_proposer_index(&self) -> ValidatorIndex {
        self.proposer_lookahead[self.slot.index_in_epoch::<P>() as usize]
    }

    /// Epochs since the last finalized checkpoint, counted from the previous epoch.
    #[must_use]
    pub fn finality_delay(&self) -> u64 {
        self.previous_epoch() - self.finalized_checkpoint.epoch
    }

    /// Whether finality has stalled long enough for the inactivity leak.
    ///
    /// The leak drains non-participants until the participants hold two thirds again.
    #[must_use]
    pub fn is_in_inactivity_leak(&self) -> bool {
        self.finality_delay() > P::MIN_EPOCHS_TO_INACTIVITY_PENALTY
    }

    /// Validators that earn rewards or penalties for the previous epoch.
    ///
    /// Slashed validators stay eligible until withdrawable, so they keep paying penalties.
    #[must_use]
    pub fn eligible_validator_indices(&self) -> Vec<ValidatorIndex> {
        let previous_epoch = self.previous_epoch();
        self.validators
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.is_active_at(previous_epoch)
                    || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
            })
            .map(|(index, _)| ValidatorIndex::from(index))
            .collect()
    }

    /// Balance already queued for partial withdrawal from a validator.
    #[must_use]
    pub fn pending_balance_to_withdraw(&self, index: ValidatorIndex) -> Gwei {
        self.pending_partial_withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.validator_index == index)
            .map(|withdrawal| withdrawal.amount)
            .sum()
    }

    /// Index of the validator with a public key, scanning the registry.
    #[must_use]
    pub fn validator_index_of(&self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.validators
            .iter()
            .position(|validator| validator.pubkey == *pubkey)
            .map(ValidatorIndex::from)
    }
}
