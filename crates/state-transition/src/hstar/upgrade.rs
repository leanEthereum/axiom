//! The upgrade from Gloas to Hstar.

use axiom_ssz::PersistentProgressiveList;
use axiom_types::{
    ChainConfig, Preset,
    accessors::CoreState,
    gloas,
    hstar::{BeaconState, PqPublicKeys},
    phase0::Fork,
};

use crate::{Caches, StateError, Upgrade};

impl<P: Preset> Upgrade for BeaconState<P> {
    type Previous = gloas::BeaconState<P>;

    /// Moves every Gloas field over, and opens an empty key registry.
    ///
    /// Every validator gets the all-zero registry entry, which has no key.
    /// The authorization queue starts empty.
    /// See `upgrade_to_<fork>` in EIP-8450.
    fn upgrade(
        pre: gloas::BeaconState<P>,
        _caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.current_epoch();
        // Invariant: one unset entry per registry member, so the lists agree on the size.
        let pq_public_keys: PersistentProgressiveList<PqPublicKeys> =
            vec![PqPublicKeys::default(); pre.validators.len()].into();

        Ok(Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.hstar_fork_version,
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
            latest_block_hash: pre.latest_block_hash,
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
            proposer_lookahead: pre.proposer_lookahead,
            builders: pre.builders,
            next_withdrawal_builder_index: pre.next_withdrawal_builder_index,
            execution_payload_availability: pre.execution_payload_availability,
            builder_pending_payments: pre.builder_pending_payments,
            builder_pending_withdrawals: pre.builder_pending_withdrawals,
            latest_execution_payload_bid: pre.latest_execution_payload_bid,
            payload_expected_withdrawals: pre.payload_expected_withdrawals,
            ptc_window: pre.ptc_window,
            pq_public_keys,
            pending_pq_key_authorizations: PersistentProgressiveList::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;
    use axiom_types::{
        Gwei, Hash32, Minimal, Version, accessors::PqRegistryState, hstar::ExecutionRequests,
        phase0::Validator,
    };

    use super::*;
    use crate::{
        BlockError, BlockProcessor, CachedState, Verification, gloas::block::ParentPayload,
    };

    /// A Gloas state with three validators, whose latest bid committed to block 0x0c.
    fn gloas_state() -> gloas::BeaconState<Minimal> {
        let mut state = gloas::BeaconState::<Minimal>::default();
        for _ in 0..3 {
            state.validators.push(Validator::default());
            state.balances.push(Gwei(32_000_000_000));
        }
        state.latest_execution_payload_bid.block_hash = Hash32([0x0c; 32]);
        state.latest_execution_payload_bid.execution_requests_root =
            gloas::ExecutionRequests::default().hash_tree_root();
        state
    }

    #[test]
    fn the_upgrade_opens_an_empty_registry_beside_the_validators() {
        let config = ChainConfig {
            hstar_fork_version: Version([0x08, 0, 0, 0x09]),
            ..ChainConfig::minimal()
        };
        let pre = gloas_state();
        let previous_version = pre.fork.current_version;

        let post = BeaconState::upgrade(pre, &mut Caches::default(), &config).unwrap();

        // Invariant: one unset entry per validator, and nobody authorized anything yet.
        assert_eq!(post.pq_public_keys().to_vec(), [PqPublicKeys::default(); 3]);
        assert!(post.pending_pq_key_authorizations().is_empty());
        assert_eq!(
            post.fork,
            Fork {
                previous_version,
                current_version: Version([0x08, 0, 0, 0x09]),
                epoch: post.current_epoch(),
            }
        );
    }

    #[test]
    fn the_first_hstar_block_cannot_report_a_full_gloas_parent() {
        // EIP-8450 changes the requests container without restating the last Gloas bid.
        //
        // Fixture state: the last Gloas bid committed to the root of Gloas's empty requests.
        // The first Hstar block reports that parent as full, in Hstar's container.
        //
        //     bid commits to   hash_tree_root(gloas::ExecutionRequests())   five fields
        //     child reports    hash_tree_root(hstar::ExecutionRequests())   six fields
        //
        // Even empty, the two roots differ, so the child is invalid.
        // The first Hstar block must build on the payload the parent itself extended.
        let config = ChainConfig::minimal();
        let mut caches = Caches::default();
        let mut post = BeaconState::upgrade(gloas_state(), &mut caches, &config).unwrap();
        let requests = ExecutionRequests::default();
        let mut processor = BlockProcessor::new(
            CachedState::new(&mut post, &mut caches),
            &config,
            Verification::Verify,
        );

        assert_eq!(
            processor.apply(&ParentPayload::new(Hash32([0x0c; 32]), &requests)),
            Err(BlockError::ParentRequestsRootMismatch {
                committed: gloas::ExecutionRequests::default().hash_tree_root(),
                actual: requests.hash_tree_root(),
            })
        );
    }
}
