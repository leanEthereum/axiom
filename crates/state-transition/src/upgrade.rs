//! The irregular state change at the Fulu fork boundary.

use axiom_ssz::Vector;
use axiom_types::{BeaconState, ChainConfig, Fork, Preset, electra};

use crate::{State, StateError};

impl<P: Preset> State<P> {
    /// Upgrades an Electra state to Fulu, at the first slot of the fork epoch.
    ///
    /// Every field carries over, and the fork version advances.
    /// The new proposer lookahead is computed from the upgraded state itself.
    ///
    /// See `upgrade_to_fulu` and `initialize_proposer_lookahead` in the Fulu fork spec.
    ///
    /// # Errors
    ///
    /// Fails when an epoch of the lookahead has no active validator.
    pub fn upgrade_from_electra(
        pre: electra::BeaconState<P>,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.slot.epoch::<P>();
        let beacon = BeaconState {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.fulu_fork_version,
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
            latest_execution_payload_header: pre.latest_execution_payload_header,
            next_withdrawal_index: pre.next_withdrawal_index,
            next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
            historical_summaries: pre.historical_summaries,
            deposit_requests_start_index: pre.deposit_requests_start_index,
            deposit_balance_to_consume: pre.deposit_balance_to_consume,
            exit_balance_to_consume: pre.exit_balance_to_consume,
            earliest_exit_epoch: pre.earliest_exit_epoch,
            consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
            earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
            pending_deposits: pre.pending_deposits,
            pending_partial_withdrawals: pre.pending_partial_withdrawals,
            pending_consolidations: pre.pending_consolidations,
            proposer_lookahead: Vector::default(),
        };

        let mut state = Self::new(beacon);
        // The lookahead spans the current epoch and the next MIN_SEED_LOOKAHEAD epochs.
        let mut lookahead = Vec::with_capacity(state.beacon.proposer_lookahead.len());
        for offset in 0..=P::MIN_SEED_LOOKAHEAD {
            lookahead.extend(state.beacon_proposer_indices(epoch + offset)?);
        }
        state.beacon.proposer_lookahead = lookahead
            .try_into()
            .map_err(|_| StateError::InvalidSyncCommittee)?;
        Ok(state)
    }
}
