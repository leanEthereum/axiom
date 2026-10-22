//! The upgrade from Bellatrix to Capella.

use axiom_ssz::PersistentList;
use axiom_types::{
    ChainConfig, Preset, Root, ValidatorIndex, WithdrawalIndex,
    accessors::CoreState,
    bellatrix,
    capella::{BeaconState, ExecutionPayloadHeader},
    phase0::Fork,
};

use crate::{Caches, StateError, Upgrade};

impl<P: Preset> Upgrade for BeaconState<P> {
    type Previous = bellatrix::BeaconState<P>;

    /// Moves every Bellatrix field over, and starts the withdrawal sweep and the summaries.
    ///
    /// The payload header gains an empty withdrawals root.
    /// See `upgrade_to_capella` in the Capella fork spec.
    fn upgrade(
        pre: bellatrix::BeaconState<P>,
        _caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.current_epoch();
        let header = pre.latest_execution_payload_header;
        Ok(Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.capella_fork_version,
                epoch,
            },
            latest_block_header: pre.latest_block_header,
            block_roots: pre.block_roots,
            state_roots: pre.state_roots,
            historical_roots: pre.historical_roots,
            eth1_data: pre.eth1_data,
            eth1_data_votes: pre.eth1_data_votes,
            eth1_deposit_index: pre.eth1_deposit_index,
            validators: pre.validators,
            balances: pre.balances,
            randao_mixes: pre.randao_mixes,
            slashings: pre.slashings,
            previous_epoch_participation: pre.previous_epoch_participation,
            current_epoch_participation: pre.current_epoch_participation,
            justification_bits: pre.justification_bits,
            previous_justified_checkpoint: pre.previous_justified_checkpoint,
            current_justified_checkpoint: pre.current_justified_checkpoint,
            finalized_checkpoint: pre.finalized_checkpoint,
            inactivity_scores: pre.inactivity_scores,
            current_sync_committee: pre.current_sync_committee,
            next_sync_committee: pre.next_sync_committee,
            latest_execution_payload_header: ExecutionPayloadHeader {
                parent_hash: header.parent_hash,
                fee_recipient: header.fee_recipient,
                state_root: header.state_root,
                receipts_root: header.receipts_root,
                logs_bloom: header.logs_bloom,
                prev_randao: header.prev_randao,
                block_number: header.block_number,
                gas_limit: header.gas_limit,
                gas_used: header.gas_used,
                timestamp: header.timestamp,
                extra_data: header.extra_data,
                base_fee_per_gas: header.base_fee_per_gas,
                block_hash: header.block_hash,
                transactions_root: header.transactions_root,
                withdrawals_root: Root::ZERO,
            },
            next_withdrawal_index: WithdrawalIndex(0),
            next_withdrawal_validator_index: ValidatorIndex(0),
            historical_summaries: PersistentList::new(),
        })
    }
}
