//! The upgrade from Deneb to Electra.

use axiom_ssz::List;
use axiom_types::{
    ChainConfig, Epoch, Gwei, Preset, Slot, ValidatorIndex,
    accessors::{CoreState, PendingQueueState},
    constants::{G2_POINT_AT_INFINITY, UNSET_DEPOSIT_REQUESTS_START_INDEX},
    deneb,
    electra::{BeaconState, PendingDeposit},
    phase0::Fork,
};

use crate::{
    ActiveBalance, Caches, StateError, Upgrade,
    electra::{churn::BalanceChurn, compounding::ExcessBalance},
};

impl<P: Preset> Upgrade for BeaconState<P> {
    type Previous = deneb::BeaconState<P>;

    /// Moves every Deneb field over, and seeds the churn queues and the deposit queue.
    ///
    /// # Algorithm
    ///
    /// 1. Every Deneb field moves over, and the fork version advances.
    /// 2. The exit queue starts after the latest scheduled exit, with a full epoch of churn.
    /// 3. The consolidation queue starts at the activation epoch, with its full churn.
    /// 4. Validators not yet activated give their balance back as pending deposits.
    /// 5. Those deposits follow eligibility order, so they activate under the balance churn.
    /// 6. Early compounding validators queue their balance above 32 ETH the same way.
    ///
    /// See `upgrade_to_electra` in the Electra fork spec.
    fn upgrade(
        pre: deneb::BeaconState<P>,
        _caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.current_epoch();
        let activation_exit_epoch = epoch.activation_exit_epoch::<P>();
        let earliest_exit_epoch = pre
            .validators
            .iter()
            .map(|validator| validator.exit_epoch)
            .filter(|exit_epoch| *exit_epoch != Epoch::FAR_FUTURE)
            .fold(activation_exit_epoch, Epoch::max)
            + 1;

        let mut post = Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.electra_fork_version,
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
            deposit_requests_start_index: UNSET_DEPOSIT_REQUESTS_START_INDEX,
            deposit_balance_to_consume: Gwei::ZERO,
            exit_balance_to_consume: Gwei::ZERO,
            earliest_exit_epoch,
            consolidation_balance_to_consume: Gwei::ZERO,
            earliest_consolidation_epoch: activation_exit_epoch,
            pending_deposits: List::new(),
            pending_partial_withdrawals: List::new(),
            pending_consolidations: List::new(),
        };

        let limits = Self::churn_limits(ActiveBalance::of(&post), config);
        post.exit_balance_to_consume = limits.exit;
        post.consolidation_balance_to_consume = limits.consolidation;

        // Validators not yet active re-enter through the queue, ordered by eligibility.
        let mut pre_activation: Vec<ValidatorIndex> = post
            .validators
            .iter()
            .enumerate()
            .filter(|(_, validator)| validator.activation_epoch == Epoch::FAR_FUTURE)
            .map(|(index, _)| ValidatorIndex::from(index))
            .collect();
        pre_activation.sort_by_key(|index| {
            (
                post.validators[index.as_usize()].activation_eligibility_epoch,
                *index,
            )
        });
        for index in pre_activation {
            let index = index.as_usize();
            let balance = post.balances[index];
            post.balances[index] = Gwei::ZERO;
            let validator = &mut post.validators[index];
            validator.effective_balance = Gwei::ZERO;
            validator.activation_eligibility_epoch = Epoch::FAR_FUTURE;
            let deposit = PendingDeposit {
                pubkey: validator.pubkey,
                withdrawal_credentials: validator.withdrawal_credentials,
                amount: balance,
                // The placeholder signature and the genesis slot mark stake already proven.
                signature: G2_POINT_AT_INFINITY,
                slot: Slot::GENESIS,
            };
            post.push_pending_deposit(deposit)
                .map_err(|source| StateError::Capacity {
                    list: "pending deposits",
                    source,
                })?;
        }

        // Early adopters of compounding credentials go through the activation churn too.
        for index in 0..post.validators.len() {
            if post.validators[index].has_compounding_withdrawal_credential() {
                ExcessBalance(ValidatorIndex::from(index)).queue(&mut post)?;
            }
        }
        Ok(post)
    }
}
