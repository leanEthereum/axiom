//! Reading a configuration from the YAML files the consensus specs and networks publish.

use std::{error::Error, fmt};

use axiom_yaml::Yaml;

use super::{BlobParameters, BlobSchedule, ChainConfig};
use crate::{Epoch, ExecutionAddress, Gwei, Version};

/// A configuration file that does not describe a valid configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The file is not a mapping of names to values.
    NotAMapping,
    /// A value does not have its field's type.
    InvalidValue(String),
    /// The preset base is neither mainnet nor minimal.
    UnknownPresetBase(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAMapping => f.write_str("configuration is not a mapping"),
            Self::InvalidValue(key) => write!(f, "configuration value {key} is invalid"),
            Self::UnknownPresetBase(base) => write!(f, "preset base {base} is unknown"),
        }
    }
}

impl Error for ConfigError {}

impl ChainConfig {
    /// A configuration read from YAML, starting from the defaults of its preset base.
    ///
    /// Keys this client does not know, such as those of future forks, are ignored.
    ///
    /// # Errors
    ///
    /// Fails when a known key has a value of the wrong type, or the preset base is unknown.
    pub fn from_yaml(yaml: &Yaml) -> Result<Self, ConfigError> {
        let mapping = yaml.as_mapping().ok_or(ConfigError::NotAMapping)?;
        let mut config = match yaml.get("PRESET_BASE").and_then(Yaml::as_str) {
            None | Some("mainnet") => Self::mainnet(),
            Some("minimal") => Self::minimal(),
            Some(other) => return Err(ConfigError::UnknownPresetBase(other.to_owned())),
        };
        for (key, value) in mapping {
            config.set(key, value)?;
        }
        Ok(config)
    }

    /// Sets one field from its YAML key and value.
    ///
    /// Unknown keys are ignored, so configs of later forks still load.
    fn set(&mut self, key: &str, value: &Yaml) -> Result<(), ConfigError> {
        // Plain counts are the bulk of the config, so they are tried first.
        if !self.set_count(key, value)? {
            self.set_typed(key, value)?;
        }
        Ok(())
    }

    /// Sets a field holding a plain integer, returning whether the key named one.
    fn set_count(&mut self, key: &str, value: &Yaml) -> Result<bool, ConfigError> {
        let number = || {
            value
                .as_u64()
                .ok_or_else(|| ConfigError::InvalidValue(key.to_owned()))
        };
        match key {
            "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT" => {
                self.min_genesis_active_validator_count = number()?;
            }
            "MIN_GENESIS_TIME" => self.min_genesis_time = number()?,
            "GENESIS_DELAY" => self.genesis_delay = number()?,
            "SLOT_DURATION_MS" => self.slot_duration_ms = number()?,
            "SECONDS_PER_ETH1_BLOCK" => self.seconds_per_eth1_block = number()?,
            "MIN_VALIDATOR_WITHDRAWABILITY_DELAY" => {
                self.min_validator_withdrawability_delay = number()?;
            }
            "SHARD_COMMITTEE_PERIOD" => self.shard_committee_period = number()?,
            "ETH1_FOLLOW_DISTANCE" => self.eth1_follow_distance = number()?,
            "PROPOSER_REORG_CUTOFF_BPS" => self.proposer_reorg_cutoff_bps = number()?,
            "ATTESTATION_DUE_BPS" => self.attestation_due_bps = number()?,
            "AGGREGATE_DUE_BPS" => self.aggregate_due_bps = number()?,
            "SYNC_MESSAGE_DUE_BPS" => self.sync_message_due_bps = number()?,
            "CONTRIBUTION_DUE_BPS" => self.contribution_due_bps = number()?,
            "INACTIVITY_SCORE_BIAS" => self.inactivity_score_bias = number()?,
            "INACTIVITY_SCORE_RECOVERY_RATE" => self.inactivity_score_recovery_rate = number()?,
            "MIN_PER_EPOCH_CHURN_LIMIT" => self.min_per_epoch_churn_limit = number()?,
            "CHURN_LIMIT_QUOTIENT" => self.churn_limit_quotient = number()?,
            "MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT" => {
                self.max_per_epoch_activation_churn_limit = number()?;
            }
            "CONSOLIDATION_CHURN_LIMIT_QUOTIENT" => {
                self.consolidation_churn_limit_quotient = number()?;
            }
            "PROPOSER_SCORE_BOOST" => self.proposer_score_boost = number()?,
            "REORG_HEAD_WEIGHT_THRESHOLD" => self.reorg_head_weight_threshold = number()?,
            "REORG_PARENT_WEIGHT_THRESHOLD" => self.reorg_parent_weight_threshold = number()?,
            "REORG_MAX_EPOCHS_SINCE_FINALIZATION" => {
                self.reorg_max_epochs_since_finalization = number()?;
            }
            "CONFIRMATION_BYZANTINE_THRESHOLD" => self.confirmation_byzantine_threshold = number()?,
            "DEPOSIT_CHAIN_ID" => self.deposit_chain_id = number()?,
            "DEPOSIT_NETWORK_ID" => self.deposit_network_id = number()?,
            "MAX_PAYLOAD_SIZE" => self.max_payload_size = number()?,
            "MAX_REQUEST_BLOCKS" => self.max_request_blocks = number()?,
            "EPOCHS_PER_SUBNET_SUBSCRIPTION" => self.epochs_per_subnet_subscription = number()?,
            "ATTESTATION_PROPAGATION_SLOT_RANGE" => {
                self.attestation_propagation_slot_range = number()?;
            }
            "MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS" => {
                self.maximum_gossip_clock_disparity_ms = number()?;
            }
            "SUBNETS_PER_NODE" => self.subnets_per_node = number()?,
            "ATTESTATION_SUBNET_COUNT" => self.attestation_subnet_count = number()?,
            "ATTESTATION_SUBNET_EXTRA_BITS" => self.attestation_subnet_extra_bits = number()?,
            "MAX_REQUEST_BLOCKS_DENEB" => self.max_request_blocks_deneb = number()?,
            "MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS" => {
                self.min_epochs_for_blob_sidecars_requests = number()?;
            }
            "BLOB_SIDECAR_SUBNET_COUNT" => self.blob_sidecar_subnet_count = number()?,
            "MAX_BLOBS_PER_BLOCK" => self.max_blobs_per_block = number()?,
            "BLOB_SIDECAR_SUBNET_COUNT_ELECTRA" => {
                self.blob_sidecar_subnet_count_electra = number()?;
            }
            "MAX_BLOBS_PER_BLOCK_ELECTRA" => self.max_blobs_per_block_electra = number()?,
            "NUMBER_OF_CUSTODY_GROUPS" => self.number_of_custody_groups = number()?,
            "DATA_COLUMN_SIDECAR_SUBNET_COUNT" => self.data_column_sidecar_subnet_count = number()?,
            "SAMPLES_PER_SLOT" => self.samples_per_slot = number()?,
            "CUSTODY_REQUIREMENT" => self.custody_requirement = number()?,
            "VALIDATOR_CUSTODY_REQUIREMENT" => self.validator_custody_requirement = number()?,
            "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS" => {
                self.min_epochs_for_data_column_sidecars_requests = number()?;
            }
            "MAXIMUM_GOSSIP_CLOCK_DISPARITY" => self.maximum_gossip_clock_disparity_ms = number()?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Sets a field holding an amount, an epoch, a version, or a structured value.
    fn set_typed(&mut self, key: &str, value: &Yaml) -> Result<(), ConfigError> {
        let invalid = || ConfigError::InvalidValue(key.to_owned());
        let number = || value.as_u64().ok_or_else(invalid);
        let bytes4 = || value.as_hex_array::<4>().ok_or_else(invalid);
        match key {
            "EJECTION_BALANCE" => self.ejection_balance = Gwei(number()?),
            "MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA" => {
                self.min_per_epoch_churn_limit_electra = Gwei(number()?);
            }
            "MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT" => {
                self.max_per_epoch_activation_exit_churn_limit = Gwei(number()?);
            }
            "BALANCE_PER_ADDITIONAL_CUSTODY_GROUP" => {
                self.balance_per_additional_custody_group = Gwei(number()?);
            }
            "ALTAIR_FORK_EPOCH" => self.altair_fork_epoch = Epoch(number()?),
            "BELLATRIX_FORK_EPOCH" => self.bellatrix_fork_epoch = Epoch(number()?),
            "CAPELLA_FORK_EPOCH" => self.capella_fork_epoch = Epoch(number()?),
            "DENEB_FORK_EPOCH" => self.deneb_fork_epoch = Epoch(number()?),
            "ELECTRA_FORK_EPOCH" => self.electra_fork_epoch = Epoch(number()?),
            "FULU_FORK_EPOCH" => self.fulu_fork_epoch = Epoch(number()?),
            "GLOAS_FORK_EPOCH" => self.gloas_fork_epoch = Epoch(number()?),
            "GENESIS_FORK_VERSION" => self.genesis_fork_version = Version(bytes4()?),
            "ALTAIR_FORK_VERSION" => self.altair_fork_version = Version(bytes4()?),
            "BELLATRIX_FORK_VERSION" => self.bellatrix_fork_version = Version(bytes4()?),
            "CAPELLA_FORK_VERSION" => self.capella_fork_version = Version(bytes4()?),
            "DENEB_FORK_VERSION" => self.deneb_fork_version = Version(bytes4()?),
            "ELECTRA_FORK_VERSION" => self.electra_fork_version = Version(bytes4()?),
            "FULU_FORK_VERSION" => self.fulu_fork_version = Version(bytes4()?),
            "GLOAS_FORK_VERSION" => self.gloas_fork_version = Version(bytes4()?),
            "MESSAGE_DOMAIN_INVALID_SNAPPY" => self.message_domain_invalid_snappy = bytes4()?,
            "MESSAGE_DOMAIN_VALID_SNAPPY" => self.message_domain_valid_snappy = bytes4()?,
            "DEPOSIT_CONTRACT_ADDRESS" => {
                self.deposit_contract_address =
                    ExecutionAddress(value.as_hex_array::<20>().ok_or_else(invalid)?);
            }
            "CONFIG_NAME" => {
                value
                    .as_str()
                    .ok_or_else(invalid)?
                    .clone_into(&mut self.config_name);
            }
            "BLOB_SCHEDULE" => {
                let entries = value
                    .as_sequence()
                    .ok_or_else(invalid)?
                    .iter()
                    .map(|entry| {
                        Some(BlobParameters {
                            epoch: Epoch(entry.get("EPOCH")?.as_u64()?),
                            max_blobs_per_block: entry.get("MAX_BLOBS_PER_BLOCK")?.as_u64()?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(invalid)?;
                self.blob_schedule = BlobSchedule::new(entries);
            }
            _ => {}
        }
        Ok(())
    }
}
