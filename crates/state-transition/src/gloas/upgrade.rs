//! The upgrade from Fulu to Gloas.

use axiom_ssz::{
    BitVector, PersistentProgressiveList, PersistentVector, ProgressiveList, Ssz, Vector,
};
use axiom_types::{
    BuilderIndex, ChainConfig, ExecutionAddress, Gwei, Preset,
    accessors::CoreState,
    constants::BUILDER_INDEX_SELF_BUILD,
    fulu,
    gloas::{BeaconState, ExecutionPayloadBid, ExecutionRequests},
    phase0::Fork,
};

use crate::{
    CachedState, Caches, StateError, Upgrade,
    gloas::{builders::BuilderDeposits, ptc::PtcWindow},
};

impl<P: Preset> Upgrade for BeaconState<P> {
    type Previous = fulu::BeaconState<P>;

    /// Moves every Fulu field over, splits the payload from the block, and opens the builder registry.
    ///
    /// # Algorithm
    ///
    /// 1. Registry-sized lists become progressive, keeping their elements, see EIP-7688.
    /// 2. The payload header gives way to the latest block hash and a self-built bid.
    /// 3. Every recent payload counts as available, and no builder is owed anything.
    /// 4. The payload timeliness committees of the current and next epochs are drawn.
    /// 5. Builder deposits waiting in the validator queue join the builder registry.
    ///
    /// See `upgrade_to_gloas` in the Gloas fork spec.
    fn upgrade(
        pre: fulu::BeaconState<P>,
        caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.current_epoch();
        let header = &pre.latest_execution_payload_header;
        let latest_execution_payload_bid = ExecutionPayloadBid {
            parent_block_hash: header.parent_hash,
            parent_block_root: pre.latest_block_header.parent_root,
            block_hash: header.block_hash,
            prev_randao: header.prev_randao,
            fee_recipient: ExecutionAddress::default(),
            gas_limit: header.gas_limit,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: pre.latest_block_header.slot,
            value: Gwei::ZERO,
            execution_payment: Gwei::ZERO,
            blob_kzg_commitments: ProgressiveList::default(),
            execution_requests_root: ExecutionRequests::default().hash_tree_root(),
        };
        let latest_block_hash = header.block_hash;
        // Every recent slot's payload counts as available at the fork.
        let mut execution_payload_availability = BitVector::new();
        for slot in 0..P::SLOTS_PER_HISTORICAL_ROOT as usize {
            execution_payload_availability.set(slot, true);
        }

        let mut post = Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.gloas_fork_version,
                epoch,
            },
            latest_block_header: pre.latest_block_header,
            block_roots: pre.block_roots,
            state_roots: pre.state_roots,
            historical_roots: pre.historical_roots,
            eth1_data: pre.eth1_data,
            eth1_data_votes: pre.eth1_data_votes,
            eth1_deposit_index: pre.eth1_deposit_index,
            validators: pre.validators.into_vec().into(),
            balances: pre.balances.into_vec().into(),
            randao_mixes: pre.randao_mixes,
            slashings: pre.slashings,
            previous_epoch_participation: pre.previous_epoch_participation.into_vec().into(),
            current_epoch_participation: pre.current_epoch_participation.into_vec().into(),
            justification_bits: pre.justification_bits,
            previous_justified_checkpoint: pre.previous_justified_checkpoint,
            current_justified_checkpoint: pre.current_justified_checkpoint,
            finalized_checkpoint: pre.finalized_checkpoint,
            inactivity_scores: pre.inactivity_scores.into_vec().into(),
            current_sync_committee: pre.current_sync_committee,
            next_sync_committee: pre.next_sync_committee,
            latest_block_hash,
            next_withdrawal_index: pre.next_withdrawal_index,
            next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
            historical_summaries: pre.historical_summaries,
            deposit_requests_start_index: pre.deposit_requests_start_index,
            deposit_balance_to_consume: pre.deposit_balance_to_consume,
            exit_balance_to_consume: pre.exit_balance_to_consume,
            earliest_exit_epoch: pre.earliest_exit_epoch,
            consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
            earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
            pending_deposits: pre.pending_deposits.into_vec().into(),
            pending_partial_withdrawals: pre.pending_partial_withdrawals.into_vec().into(),
            pending_consolidations: pre.pending_consolidations.into_vec().into(),
            proposer_lookahead: pre.proposer_lookahead,
            builders: PersistentProgressiveList::default(),
            next_withdrawal_builder_index: BuilderIndex(0),
            execution_payload_availability,
            builder_pending_payments: Vector::default(),
            builder_pending_withdrawals: PersistentProgressiveList::default(),
            latest_execution_payload_bid,
            payload_expected_withdrawals: ProgressiveList::default(),
            ptc_window: PersistentVector::default(),
        };

        let mut state = CachedState::new(&mut post, caches);
        PtcWindow::initialize(&mut state)?;
        BuilderDeposits::new(config).onboard(&mut state)?;
        Ok(post)
    }
}
