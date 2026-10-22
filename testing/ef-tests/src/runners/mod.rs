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

use axiom_types::{ChainConfig, Epoch, Preset};
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

use crate::{Case, Failure};

/// Field names of the beacon state, in order, for readable mismatch reports.
pub const BEACON_STATE_FIELDS: [&str; 38] = [
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
];

/// The configuration of one case: its own file when it ships one, the preset's otherwise.
///
/// # Errors
///
/// Fails when the case's configuration file does not parse.
pub fn case_config<P: Preset>(case: &Case) -> Result<ChainConfig, Failure> {
    if !case.has("config.yaml") {
        return Ok(config_of::<P>());
    }
    ChainConfig::from_yaml(&case.yaml("config.yaml")?)
        .map_err(|error| Failure(format!("config.yaml: {error}")))
}

/// The configuration the vectors of a preset were generated with.
///
/// The generator activates every fork up to the one under test at genesis.
/// Fork epochs then read as zero, whatever the preset's configuration file says.
#[must_use]
pub fn config_of<P: Preset>() -> ChainConfig {
    let mut config = if P::NAME == "mainnet" {
        ChainConfig::mainnet()
    } else {
        ChainConfig::minimal()
    };
    config.altair_fork_epoch = Epoch::GENESIS;
    config.bellatrix_fork_epoch = Epoch::GENESIS;
    config.capella_fork_epoch = Epoch::GENESIS;
    config.deneb_fork_epoch = Epoch::GENESIS;
    config.electra_fork_epoch = Epoch::GENESIS;
    config.fulu_fork_epoch = Epoch::GENESIS;
    config
}
