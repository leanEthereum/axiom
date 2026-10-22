//! Runtime configuration: the values an operator or a test network chooses.
//!
//! Presets fix the shape of types at compile time.
//! A configuration only changes behaviour, so it is read at startup and checked at the boundary.
//!
//! Values come from `configs/{mainnet,minimal}.yaml` in the consensus specs.

mod blob_schedule;
mod fork_name;
mod yaml;

pub use blob_schedule::{BlobParameters, BlobSchedule};
pub use fork_name::ForkName;
pub use yaml::ConfigError;

use crate::{Epoch, ExecutionAddress, Gwei, Version};

/// Every runtime parameter of a beacon chain network.
///
/// Fields keep the spec's names in lowercase, so each one can be searched in the spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainConfig {
    /// Name of the configuration, such as mainnet.
    pub config_name: String,

    /// Validators needed at genesis.
    pub min_genesis_active_validator_count: u64,
    /// Earliest genesis time, in Unix seconds.
    pub min_genesis_time: u64,
    /// Delay between the genesis trigger and genesis, in seconds.
    pub genesis_delay: u64,

    /// Fork version at genesis.
    pub genesis_fork_version: Version,
    /// Fork version of Altair.
    pub altair_fork_version: Version,
    /// Activation epoch of Altair.
    pub altair_fork_epoch: Epoch,
    /// Fork version of Bellatrix.
    pub bellatrix_fork_version: Version,
    /// Activation epoch of Bellatrix.
    pub bellatrix_fork_epoch: Epoch,
    /// Fork version of Capella.
    pub capella_fork_version: Version,
    /// Activation epoch of Capella.
    pub capella_fork_epoch: Epoch,
    /// Fork version of Deneb.
    pub deneb_fork_version: Version,
    /// Activation epoch of Deneb.
    pub deneb_fork_epoch: Epoch,
    /// Fork version of Electra.
    pub electra_fork_version: Version,
    /// Activation epoch of Electra.
    pub electra_fork_epoch: Epoch,
    /// Fork version of Fulu.
    pub fulu_fork_version: Version,
    /// Activation epoch of Fulu.
    pub fulu_fork_epoch: Epoch,
    /// Fork version of Gloas.
    pub gloas_fork_version: Version,
    /// Activation epoch of Gloas.
    pub gloas_fork_epoch: Epoch,

    /// Length of a slot, in milliseconds.
    pub slot_duration_ms: u64,
    /// Expected time between execution blocks, in seconds.
    pub seconds_per_eth1_block: u64,
    /// Epochs between an exit and the balance becoming withdrawable.
    pub min_validator_withdrawability_delay: u64,
    /// Epochs a validator must serve before it may exit.
    pub shard_committee_period: u64,
    /// Execution blocks the eth1 data vote trails the head by.
    pub eth1_follow_distance: u64,

    /// Point in the slot, in basis points, after which a late head may be reorged.
    pub proposer_reorg_cutoff_bps: u64,
    /// Point in the slot, in basis points, by which attestations are due.
    pub attestation_due_bps: u64,
    /// Point in the slot, in basis points, by which aggregates are due.
    pub aggregate_due_bps: u64,
    /// Point in the slot, in basis points, by which sync messages are due.
    pub sync_message_due_bps: u64,
    /// Point in the slot, in basis points, by which sync contributions are due.
    pub contribution_due_bps: u64,

    /// Inactivity score added per epoch of missed target votes during a leak.
    pub inactivity_score_bias: u64,
    /// Inactivity score removed per epoch outside a leak.
    pub inactivity_score_recovery_rate: u64,
    /// Effective balance at or below which a validator is ejected.
    pub ejection_balance: Gwei,
    /// Floor of the validator churn per epoch, in validators.
    pub min_per_epoch_churn_limit: u64,
    /// Divides the active validator count into the churn per epoch.
    pub churn_limit_quotient: u64,
    /// Cap of the activation churn per epoch, in validators.
    pub max_per_epoch_activation_churn_limit: u64,
    /// Floor of the balance churn per epoch, see EIP-7251.
    pub min_per_epoch_churn_limit_electra: Gwei,
    /// Cap of the activation and exit balance churn per epoch.
    pub max_per_epoch_activation_exit_churn_limit: Gwei,
    /// Divides the total active balance into the consolidation churn.
    pub consolidation_churn_limit_quotient: u64,

    /// Weight of proposer boost, as a percentage of one committee's weight.
    pub proposer_score_boost: u64,
    /// Head weight below which a late head may be reorged, as a committee percentage.
    pub reorg_head_weight_threshold: u64,
    /// Parent weight above which a late head may be reorged, as a committee percentage.
    pub reorg_parent_weight_threshold: u64,
    /// Epochs since finalization beyond which late heads are never reorged.
    pub reorg_max_epochs_since_finalization: u64,
    /// Byzantine stake fraction, in percent, the fast confirmation rule tolerates.
    pub confirmation_byzantine_threshold: u64,

    /// Chain identifier of the deposit contract's chain.
    pub deposit_chain_id: u64,
    /// Network identifier of the deposit contract's chain.
    pub deposit_network_id: u64,
    /// Address of the deposit contract.
    pub deposit_contract_address: ExecutionAddress,

    /// Largest uncompressed gossip or request payload, in bytes.
    pub max_payload_size: u64,
    /// Blocks per request.
    pub max_request_blocks: u64,
    /// Epochs a node stays subscribed to a long-lived subnet.
    pub epochs_per_subnet_subscription: u64,
    /// Slots an attestation stays valid for gossip.
    pub attestation_propagation_slot_range: u64,
    /// Clock disparity tolerated on gossip, in milliseconds.
    pub maximum_gossip_clock_disparity_ms: u64,
    /// Domain of message identifiers for undecodable snappy payloads.
    pub message_domain_invalid_snappy: [u8; 4],
    /// Domain of message identifiers for decodable snappy payloads.
    pub message_domain_valid_snappy: [u8; 4],
    /// Long-lived attestation subnets per node.
    pub subnets_per_node: u64,
    /// Attestation subnets.
    pub attestation_subnet_count: u64,
    /// Extra bits of node identifier used to pick subnets.
    pub attestation_subnet_extra_bits: u64,
    /// Blocks per request from Deneb on.
    pub max_request_blocks_deneb: u64,
    /// Epochs of blob sidecars a node must serve.
    pub min_epochs_for_blob_sidecars_requests: u64,
    /// Blob sidecar subnets before Electra.
    pub blob_sidecar_subnet_count: u64,
    /// Blobs per block before Electra.
    pub max_blobs_per_block: u64,
    /// Blob sidecar subnets in Electra.
    pub blob_sidecar_subnet_count_electra: u64,
    /// Blobs per block in Electra, before any blob schedule entry.
    pub max_blobs_per_block_electra: u64,

    /// Custody groups the columns are partitioned into.
    pub number_of_custody_groups: u64,
    /// Data column sidecar subnets.
    pub data_column_sidecar_subnet_count: u64,
    /// Columns a node samples per slot.
    pub samples_per_slot: u64,
    /// Custody groups every node holds.
    pub custody_requirement: u64,
    /// Custody groups a node with validators holds at least.
    pub validator_custody_requirement: u64,
    /// Attached balance that earns one more custody group.
    pub balance_per_additional_custody_group: Gwei,
    /// Epochs of data columns a node must serve.
    pub min_epochs_for_data_column_sidecars_requests: u64,

    /// Blob limits that change at fixed epochs, see EIP-7892.
    pub blob_schedule: BlobSchedule,
}

impl ChainConfig {
    /// The mainnet configuration.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            config_name: "mainnet".into(),
            min_genesis_active_validator_count: 16_384,
            min_genesis_time: 1_606_824_000,
            genesis_delay: 604_800,
            genesis_fork_version: Version([0x00, 0, 0, 0]),
            altair_fork_version: Version([0x01, 0, 0, 0]),
            altair_fork_epoch: Epoch(74_240),
            bellatrix_fork_version: Version([0x02, 0, 0, 0]),
            bellatrix_fork_epoch: Epoch(144_896),
            capella_fork_version: Version([0x03, 0, 0, 0]),
            capella_fork_epoch: Epoch(194_048),
            deneb_fork_version: Version([0x04, 0, 0, 0]),
            deneb_fork_epoch: Epoch(269_568),
            electra_fork_version: Version([0x05, 0, 0, 0]),
            electra_fork_epoch: Epoch(364_032),
            fulu_fork_version: Version([0x06, 0, 0, 0]),
            fulu_fork_epoch: Epoch(411_392),
            gloas_fork_version: Version([0x07, 0, 0, 0]),
            gloas_fork_epoch: Epoch::FAR_FUTURE,
            slot_duration_ms: 12_000,
            seconds_per_eth1_block: 14,
            min_validator_withdrawability_delay: 256,
            shard_committee_period: 256,
            eth1_follow_distance: 2048,
            proposer_reorg_cutoff_bps: 1667,
            attestation_due_bps: 3333,
            aggregate_due_bps: 6667,
            sync_message_due_bps: 3333,
            contribution_due_bps: 6667,
            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            ejection_balance: Gwei(16_000_000_000),
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 65_536,
            max_per_epoch_activation_churn_limit: 8,
            min_per_epoch_churn_limit_electra: Gwei(128_000_000_000),
            max_per_epoch_activation_exit_churn_limit: Gwei(256_000_000_000),
            consolidation_churn_limit_quotient: 65_536,
            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,
            confirmation_byzantine_threshold: 25,
            deposit_chain_id: 1,
            deposit_network_id: 1,
            deposit_contract_address: ExecutionAddress([
                0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe,
                0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
            ]),
            max_payload_size: 10_485_760,
            max_request_blocks: 1024,
            epochs_per_subnet_subscription: 256,
            attestation_propagation_slot_range: 32,
            maximum_gossip_clock_disparity_ms: 500,
            message_domain_invalid_snappy: [0x00, 0, 0, 0],
            message_domain_valid_snappy: [0x01, 0, 0, 0],
            subnets_per_node: 2,
            attestation_subnet_count: 64,
            attestation_subnet_extra_bits: 0,
            max_request_blocks_deneb: 128,
            min_epochs_for_blob_sidecars_requests: 4096,
            blob_sidecar_subnet_count: 6,
            max_blobs_per_block: 6,
            blob_sidecar_subnet_count_electra: 9,
            max_blobs_per_block_electra: 9,
            number_of_custody_groups: 128,
            data_column_sidecar_subnet_count: 128,
            samples_per_slot: 8,
            custody_requirement: 4,
            validator_custody_requirement: 8,
            balance_per_additional_custody_group: Gwei(32_000_000_000),
            min_epochs_for_data_column_sidecars_requests: 4096,
            blob_schedule: BlobSchedule::new(vec![
                BlobParameters {
                    epoch: Epoch(412_672),
                    max_blobs_per_block: 15,
                },
                BlobParameters {
                    epoch: Epoch(419_072),
                    max_blobs_per_block: 21,
                },
            ]),
        }
    }

    /// The minimal configuration, which every fork starts disabled in.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            config_name: "minimal".into(),
            min_genesis_active_validator_count: 64,
            min_genesis_time: 1_578_009_600,
            genesis_delay: 300,
            genesis_fork_version: Version([0x00, 0, 0, 0x01]),
            altair_fork_version: Version([0x01, 0, 0, 0x01]),
            altair_fork_epoch: Epoch::FAR_FUTURE,
            bellatrix_fork_version: Version([0x02, 0, 0, 0x01]),
            bellatrix_fork_epoch: Epoch::FAR_FUTURE,
            capella_fork_version: Version([0x03, 0, 0, 0x01]),
            capella_fork_epoch: Epoch::FAR_FUTURE,
            deneb_fork_version: Version([0x04, 0, 0, 0x01]),
            deneb_fork_epoch: Epoch::FAR_FUTURE,
            electra_fork_version: Version([0x05, 0, 0, 0x01]),
            electra_fork_epoch: Epoch::FAR_FUTURE,
            fulu_fork_version: Version([0x06, 0, 0, 0x01]),
            fulu_fork_epoch: Epoch::FAR_FUTURE,
            gloas_fork_version: Version([0x07, 0, 0, 0x01]),
            gloas_fork_epoch: Epoch::FAR_FUTURE,
            slot_duration_ms: 6000,
            seconds_per_eth1_block: 14,
            min_validator_withdrawability_delay: 256,
            shard_committee_period: 64,
            eth1_follow_distance: 16,
            min_per_epoch_churn_limit: 2,
            churn_limit_quotient: 32,
            max_per_epoch_activation_churn_limit: 4,
            min_per_epoch_churn_limit_electra: Gwei(64_000_000_000),
            max_per_epoch_activation_exit_churn_limit: Gwei(128_000_000_000),
            consolidation_churn_limit_quotient: 32,
            deposit_chain_id: 5,
            deposit_network_id: 5,
            deposit_contract_address: ExecutionAddress([
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
                0x90, 0x12, 0x34, 0x56, 0x78, 0x90,
            ]),
            blob_schedule: BlobSchedule::new(Vec::new()),
            ..Self::mainnet()
        }
    }

    /// Fork active at an epoch.
    #[must_use]
    pub fn fork_at(&self, epoch: Epoch) -> ForkName {
        ForkName::ALL
            .into_iter()
            .rev()
            .find(|fork| self.fork_epoch(*fork) <= epoch)
            .unwrap_or(ForkName::Phase0)
    }

    /// Activation epoch of a fork.
    #[must_use]
    pub const fn fork_epoch(&self, fork: ForkName) -> Epoch {
        match fork {
            ForkName::Phase0 => Epoch::GENESIS,
            ForkName::Altair => self.altair_fork_epoch,
            ForkName::Bellatrix => self.bellatrix_fork_epoch,
            ForkName::Capella => self.capella_fork_epoch,
            ForkName::Deneb => self.deneb_fork_epoch,
            ForkName::Electra => self.electra_fork_epoch,
            ForkName::Fulu => self.fulu_fork_epoch,
            ForkName::Gloas => self.gloas_fork_epoch,
        }
    }

    /// Version of a fork.
    #[must_use]
    pub const fn fork_version(&self, fork: ForkName) -> Version {
        match fork {
            ForkName::Phase0 => self.genesis_fork_version,
            ForkName::Altair => self.altair_fork_version,
            ForkName::Bellatrix => self.bellatrix_fork_version,
            ForkName::Capella => self.capella_fork_version,
            ForkName::Deneb => self.deneb_fork_version,
            ForkName::Electra => self.electra_fork_version,
            ForkName::Fulu => self.fulu_fork_version,
            ForkName::Gloas => self.gloas_fork_version,
        }
    }

    /// Version of the fork active at an epoch.
    ///
    /// See `compute_fork_version` in the Fulu fork spec.
    #[must_use]
    pub fn fork_version_at(&self, epoch: Epoch) -> Version {
        self.fork_version(self.fork_at(epoch))
    }

    /// Blob limit and the epoch it started at, for an epoch.
    ///
    /// Before the first schedule entry, the Electra limit applies.
    /// See `get_blob_parameters` in the Fulu beacon chain spec.
    #[must_use]
    pub fn blob_parameters(&self, epoch: Epoch) -> BlobParameters {
        self.blob_schedule.at(epoch).unwrap_or(BlobParameters {
            epoch: self.electra_fork_epoch,
            max_blobs_per_block: self.max_blobs_per_block_electra,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_fork_schedule_resolves_by_epoch() {
        // Fixture state: Fulu activated at epoch 411392 on mainnet.
        let config = ChainConfig::mainnet();

        assert_eq!(config.fork_at(Epoch(411_391)), ForkName::Electra);
        assert_eq!(config.fork_at(Epoch(411_392)), ForkName::Fulu);
        assert_eq!(
            config.fork_version_at(Epoch(500_000)),
            Version([0x06, 0, 0, 0])
        );
    }

    #[test]
    fn minimal_starts_and_stays_at_phase0() {
        // Every fork epoch is the far future in the minimal configuration.
        assert_eq!(
            ChainConfig::minimal().fork_at(Epoch(1_000)),
            ForkName::Phase0
        );
    }

    #[test]
    fn blob_parameters_fall_back_to_electra() {
        // Before the first schedule entry at 412672, the Electra limit of 9 applies.
        let config = ChainConfig::mainnet();

        assert_eq!(
            config.blob_parameters(Epoch(412_000)),
            BlobParameters {
                epoch: Epoch(364_032),
                max_blobs_per_block: 9
            }
        );
        assert_eq!(
            config.blob_parameters(Epoch(420_000)).max_blobs_per_block,
            21
        );
    }
}
