//! One runner per kind of consensus spec vector.

mod blocks;
mod chain;
mod epoch_processing;
mod fork;
mod fork_choice;
mod gossip;
mod light_client;
mod merkle_proof;
mod networking;
mod operations;
mod rewards;
mod shuffling;
mod ssz_static;
mod transition;

pub use blocks::Blocks;
pub use chain::ChainReplay;
pub use epoch_processing::EpochProcessing;
pub use fork::Fork;
pub use fork_choice::StoreReplay;
pub use light_client::LightClient;
pub use merkle_proof::MerkleProofs;
pub use networking::Networking;
pub use operations::Operations;
pub use rewards::Rewards;
pub use shuffling::Shuffling;
pub use ssz_static::SszStatic;
pub use transition::Transition;

use crate::FieldNames;

/// Field names of the beacon state, in order, for readable mismatch reports.
pub const BEACON_STATE_FIELDS: FieldNames = FieldNames(&[
    "genesis_time",
    "genesis_validators_root",
    "slot",
    "fork",
    "latest_block_header",
    "block_roots",
    "state_roots",
    "historical_roots",
    "eth1_data",
    "eth1_data_votes",
    "eth1_deposit_index",
    "validators",
    "balances",
    "randao_mixes",
    "slashings",
    "previous_epoch_participation",
    "current_epoch_participation",
    "justification_bits",
    "previous_justified_checkpoint",
    "current_justified_checkpoint",
    "finalized_checkpoint",
    "inactivity_scores",
    "current_sync_committee",
    "next_sync_committee",
    "latest_execution_payload_header",
    "next_withdrawal_index",
    "next_withdrawal_validator_index",
    "historical_summaries",
    "deposit_requests_start_index",
    "deposit_balance_to_consume",
    "exit_balance_to_consume",
    "earliest_exit_epoch",
    "consolidation_balance_to_consume",
    "earliest_consolidation_epoch",
    "pending_deposits",
    "pending_partial_withdrawals",
    "pending_consolidations",
    "proposer_lookahead",
]);
