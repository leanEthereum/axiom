//! The upgrade from Altair to Bellatrix.

use axiom_types::{
    ChainConfig, Preset,
    accessors::CoreState,
    altair,
    bellatrix::{BeaconState, ExecutionPayloadHeader},
    phase0::Fork,
};

use crate::{Caches, StateError, Upgrade};

impl<P: Preset> Upgrade for BeaconState<P> {
    type Previous = altair::BeaconState<P>;

    /// Moves every Altair field over, with an empty execution payload header.
    ///
    /// The empty header marks the merge as not yet happened.
    /// See `upgrade_to_bellatrix` in the Bellatrix fork spec.
    fn upgrade(
        pre: altair::BeaconState<P>,
        _caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.current_epoch();
        Ok(Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.bellatrix_fork_version,
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
            latest_execution_payload_header: ExecutionPayloadHeader::default(),
        })
    }
}
