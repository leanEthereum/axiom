//! The beacon state with blob-era payload headers, from the Deneb beacon chain spec.

use axiom_json::Json;
use axiom_types::{Preset, deneb::BeaconState};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for BeaconState<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("genesis_time", self.genesis_time.to_json()),
            (
                "genesis_validators_root",
                self.genesis_validators_root.to_json(),
            ),
            ("slot", self.slot.to_json()),
            ("fork", self.fork.to_json()),
            ("latest_block_header", self.latest_block_header.to_json()),
            ("block_roots", self.block_roots.to_json()),
            ("state_roots", self.state_roots.to_json()),
            ("historical_roots", self.historical_roots.to_json()),
            ("eth1_data", self.eth1_data.to_json()),
            ("eth1_data_votes", self.eth1_data_votes.to_json()),
            ("eth1_deposit_index", self.eth1_deposit_index.to_json()),
            ("validators", self.validators.to_json()),
            ("balances", self.balances.to_json()),
            ("randao_mixes", self.randao_mixes.to_json()),
            ("slashings", self.slashings.to_json()),
            (
                "previous_epoch_participation",
                self.previous_epoch_participation.to_json(),
            ),
            (
                "current_epoch_participation",
                self.current_epoch_participation.to_json(),
            ),
            ("justification_bits", self.justification_bits.to_json()),
            (
                "previous_justified_checkpoint",
                self.previous_justified_checkpoint.to_json(),
            ),
            (
                "current_justified_checkpoint",
                self.current_justified_checkpoint.to_json(),
            ),
            ("finalized_checkpoint", self.finalized_checkpoint.to_json()),
            ("inactivity_scores", self.inactivity_scores.to_json()),
            (
                "current_sync_committee",
                self.current_sync_committee.to_json(),
            ),
            ("next_sync_committee", self.next_sync_committee.to_json()),
            (
                "latest_execution_payload_header",
                self.latest_execution_payload_header.to_json(),
            ),
            (
                "next_withdrawal_index",
                self.next_withdrawal_index.to_json(),
            ),
            (
                "next_withdrawal_validator_index",
                self.next_withdrawal_validator_index.to_json(),
            ),
            ("historical_summaries", self.historical_summaries.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            genesis_time: fields.required("genesis_time")?,
            genesis_validators_root: fields.required("genesis_validators_root")?,
            slot: fields.required("slot")?,
            fork: fields.required("fork")?,
            latest_block_header: fields.required("latest_block_header")?,
            block_roots: fields.required("block_roots")?,
            state_roots: fields.required("state_roots")?,
            historical_roots: fields.required("historical_roots")?,
            eth1_data: fields.required("eth1_data")?,
            eth1_data_votes: fields.required("eth1_data_votes")?,
            eth1_deposit_index: fields.required("eth1_deposit_index")?,
            validators: fields.required("validators")?,
            balances: fields.required("balances")?,
            randao_mixes: fields.required("randao_mixes")?,
            slashings: fields.required("slashings")?,
            previous_epoch_participation: fields.required("previous_epoch_participation")?,
            current_epoch_participation: fields.required("current_epoch_participation")?,
            justification_bits: fields.required("justification_bits")?,
            previous_justified_checkpoint: fields.required("previous_justified_checkpoint")?,
            current_justified_checkpoint: fields.required("current_justified_checkpoint")?,
            finalized_checkpoint: fields.required("finalized_checkpoint")?,
            inactivity_scores: fields.required("inactivity_scores")?,
            current_sync_committee: fields.required("current_sync_committee")?,
            next_sync_committee: fields.required("next_sync_committee")?,
            latest_execution_payload_header: fields.required("latest_execution_payload_header")?,
            next_withdrawal_index: fields.required("next_withdrawal_index")?,
            next_withdrawal_validator_index: fields.required("next_withdrawal_validator_index")?,
            historical_summaries: fields.required("historical_summaries")?,
        })
    }
}
