//! Reading a configuration from the YAML files the consensus specs and networks publish.

use axiom_yaml::Yaml;
use thiserror::Error;

use super::{BlobParameters, BlobSchedule, ChainConfig};
use crate::{Epoch, ExecutionAddress, Gwei, Version};

/// A configuration file that does not describe a valid configuration.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The file is not a mapping of names to values.
    #[error("configuration is not a mapping")]
    NotAMapping,
    /// A value does not have its field's type.
    #[error("configuration value {key} is not {expected}")]
    InvalidValue {
        /// The key whose value is malformed, such as `SECONDS_PER_SLOT`.
        key: String,
        /// The shape the key's field requires, such as an integer.
        expected: &'static str,
    },
    /// The preset base is neither mainnet nor minimal.
    #[error("preset base {0} is unknown")]
    UnknownPresetBase(String),
}

/// One key and value of a configuration file.
#[derive(Clone, Copy, Debug)]
pub(super) struct ConfigEntry<'a> {
    /// The key, such as `SECONDS_PER_SLOT`.
    key: &'a str,
    /// The value.
    value: &'a Yaml,
}

impl<'a> ConfigEntry<'a> {
    /// An entry of a configuration file.
    pub(super) const fn new(key: &'a str, value: &'a Yaml) -> Self {
        Self { key, value }
    }

    /// Sets the field this entry names.
    ///
    /// Unknown keys are ignored, so configs of later forks still load.
    pub(super) fn apply_to(self, config: &mut ChainConfig) -> Result<(), ConfigError> {
        // Plain counts are the bulk of the config, so they are tried first.
        if !self.set_count(config)? {
            self.set_typed(config)?;
        }
        Ok(())
    }

    /// Sets a field holding a plain integer, returning whether the key named one.
    fn set_count(self, config: &mut ChainConfig) -> Result<bool, ConfigError> {
        let Self { key, value } = self;
        let number = || {
            value
                .as_u64()
                .ok_or_else(|| ConfigError::InvalidValue {
                    key: key.to_owned(),
                    expected: "an integer",
                })
        };
        match key {
            "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT" => {
                config.min_genesis_active_validator_count = number()?;
            }
            "MIN_GENESIS_TIME" => config.min_genesis_time = number()?,
            "GENESIS_DELAY" => config.genesis_delay = number()?,
            "SLOT_DURATION_MS" => config.slot_duration_ms = number()?,
            "SECONDS_PER_ETH1_BLOCK" => config.seconds_per_eth1_block = number()?,
            "MIN_VALIDATOR_WITHDRAWABILITY_DELAY" => {
                config.min_validator_withdrawability_delay = number()?;
            }
            "SHARD_COMMITTEE_PERIOD" => config.shard_committee_period = number()?,
            "ETH1_FOLLOW_DISTANCE" => config.eth1_follow_distance = number()?,
            "PROPOSER_REORG_CUTOFF_BPS" => config.proposer_reorg_cutoff_bps = number()?,
            "ATTESTATION_DUE_BPS" => config.attestation_due_bps = number()?,
            "AGGREGATE_DUE_BPS" => config.aggregate_due_bps = number()?,
            "SYNC_MESSAGE_DUE_BPS" => config.sync_message_due_bps = number()?,
            "CONTRIBUTION_DUE_BPS" => config.contribution_due_bps = number()?,
            "INACTIVITY_SCORE_BIAS" => config.inactivity_score_bias = number()?,
            "INACTIVITY_SCORE_RECOVERY_RATE" => config.inactivity_score_recovery_rate = number()?,
            "MIN_PER_EPOCH_CHURN_LIMIT" => config.min_per_epoch_churn_limit = number()?,
            "CHURN_LIMIT_QUOTIENT" => config.churn_limit_quotient = number()?,
            "MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT" => {
                config.max_per_epoch_activation_churn_limit = number()?;
            }
            "CONSOLIDATION_CHURN_LIMIT_QUOTIENT" => {
                config.consolidation_churn_limit_quotient = number()?;
            }
            "PROPOSER_SCORE_BOOST" => config.proposer_score_boost = number()?,
            "REORG_HEAD_WEIGHT_THRESHOLD" => config.reorg_head_weight_threshold = number()?,
            "REORG_PARENT_WEIGHT_THRESHOLD" => config.reorg_parent_weight_threshold = number()?,
            "REORG_MAX_EPOCHS_SINCE_FINALIZATION" => {
                config.reorg_max_epochs_since_finalization = number()?;
            }
            "CONFIRMATION_BYZANTINE_THRESHOLD" => {
                config.confirmation_byzantine_threshold = number()?;
            }
            "DEPOSIT_CHAIN_ID" => config.deposit_chain_id = number()?,
            "DEPOSIT_NETWORK_ID" => config.deposit_network_id = number()?,
            "MAX_PAYLOAD_SIZE" => config.max_payload_size = number()?,
            "MAX_REQUEST_BLOCKS" => config.max_request_blocks = number()?,
            "EPOCHS_PER_SUBNET_SUBSCRIPTION" => config.epochs_per_subnet_subscription = number()?,
            "ATTESTATION_PROPAGATION_SLOT_RANGE" => {
                config.attestation_propagation_slot_range = number()?;
            }
            // Both spellings of the key set the same value.
            "MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS" | "MAXIMUM_GOSSIP_CLOCK_DISPARITY" => {
                config.maximum_gossip_clock_disparity_ms = number()?;
            }
            "SUBNETS_PER_NODE" => config.subnets_per_node = number()?,
            "ATTESTATION_SUBNET_COUNT" => config.attestation_subnet_count = number()?,
            "ATTESTATION_SUBNET_EXTRA_BITS" => config.attestation_subnet_extra_bits = number()?,
            "MAX_REQUEST_BLOCKS_DENEB" => config.max_request_blocks_deneb = number()?,
            "MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS" => {
                config.min_epochs_for_blob_sidecars_requests = number()?;
            }
            "BLOB_SIDECAR_SUBNET_COUNT" => config.blob_sidecar_subnet_count = number()?,
            "MAX_BLOBS_PER_BLOCK" => config.max_blobs_per_block = number()?,
            "BLOB_SIDECAR_SUBNET_COUNT_ELECTRA" => {
                config.blob_sidecar_subnet_count_electra = number()?;
            }
            "MAX_BLOBS_PER_BLOCK_ELECTRA" => config.max_blobs_per_block_electra = number()?,
            "NUMBER_OF_CUSTODY_GROUPS" => config.number_of_custody_groups = number()?,
            "DATA_COLUMN_SIDECAR_SUBNET_COUNT" => {
                config.data_column_sidecar_subnet_count = number()?;
            }
            "SAMPLES_PER_SLOT" => config.samples_per_slot = number()?,
            "CUSTODY_REQUIREMENT" => config.custody_requirement = number()?,
            "VALIDATOR_CUSTODY_REQUIREMENT" => config.validator_custody_requirement = number()?,
            "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS" => {
                config.min_epochs_for_data_column_sidecars_requests = number()?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Sets a field holding an amount, an epoch, a version, or a structured value.
    fn set_typed(self, config: &mut ChainConfig) -> Result<(), ConfigError> {
        let Self { key, value } = self;
        let invalid = |expected| ConfigError::InvalidValue {
            key: key.to_owned(),
            expected,
        };
        let number = || value.as_u64().ok_or_else(|| invalid("an integer"));
        let bytes4 = || {
            value
                .as_hex_array::<4>()
                .ok_or_else(|| invalid("4 hex bytes"))
        };
        match key {
            "EJECTION_BALANCE" => config.ejection_balance = Gwei(number()?),
            "MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA" => {
                config.min_per_epoch_churn_limit_electra = Gwei(number()?);
            }
            "MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT" => {
                config.max_per_epoch_activation_exit_churn_limit = Gwei(number()?);
            }
            "BALANCE_PER_ADDITIONAL_CUSTODY_GROUP" => {
                config.balance_per_additional_custody_group = Gwei(number()?);
            }
            "ALTAIR_FORK_EPOCH" => config.altair_fork_epoch = Epoch(number()?),
            "BELLATRIX_FORK_EPOCH" => config.bellatrix_fork_epoch = Epoch(number()?),
            "CAPELLA_FORK_EPOCH" => config.capella_fork_epoch = Epoch(number()?),
            "DENEB_FORK_EPOCH" => config.deneb_fork_epoch = Epoch(number()?),
            "ELECTRA_FORK_EPOCH" => config.electra_fork_epoch = Epoch(number()?),
            "FULU_FORK_EPOCH" => config.fulu_fork_epoch = Epoch(number()?),
            "GLOAS_FORK_EPOCH" => config.gloas_fork_epoch = Epoch(number()?),
            "GENESIS_FORK_VERSION" => config.genesis_fork_version = Version(bytes4()?),
            "ALTAIR_FORK_VERSION" => config.altair_fork_version = Version(bytes4()?),
            "BELLATRIX_FORK_VERSION" => config.bellatrix_fork_version = Version(bytes4()?),
            "CAPELLA_FORK_VERSION" => config.capella_fork_version = Version(bytes4()?),
            "DENEB_FORK_VERSION" => config.deneb_fork_version = Version(bytes4()?),
            "ELECTRA_FORK_VERSION" => config.electra_fork_version = Version(bytes4()?),
            "FULU_FORK_VERSION" => config.fulu_fork_version = Version(bytes4()?),
            "GLOAS_FORK_VERSION" => config.gloas_fork_version = Version(bytes4()?),
            "MESSAGE_DOMAIN_INVALID_SNAPPY" => config.message_domain_invalid_snappy = bytes4()?,
            "MESSAGE_DOMAIN_VALID_SNAPPY" => config.message_domain_valid_snappy = bytes4()?,
            "DEPOSIT_CONTRACT_ADDRESS" => {
                config.deposit_contract_address =
                    ExecutionAddress(value
                        .as_hex_array::<20>()
                        .ok_or_else(|| invalid("20 hex bytes"))?);
            }
            "CONFIG_NAME" => {
                value
                    .as_str()
                    .ok_or_else(|| invalid("a string"))?
                    .clone_into(&mut config.config_name);
            }
            "BLOB_SCHEDULE" => {
                let entries = value
                    .as_sequence()
                    .ok_or_else(|| invalid("a sequence"))?
                    .iter()
                    .map(|entry| {
                        Some(BlobParameters {
                            epoch: Epoch(entry.get("EPOCH")?.as_u64()?),
                            max_blobs_per_block: entry.get("MAX_BLOBS_PER_BLOCK")?.as_u64()?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| invalid("a list of epochs and blob limits"))?;
                config.blob_schedule = BlobSchedule::new(entries);
            }
            _ => {}
        }
        Ok(())
    }
}
