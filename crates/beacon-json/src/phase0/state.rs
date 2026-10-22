//! The beacon state and its registry, from the phase0 beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    phase0::{BeaconState, HistoricalBatch, PendingAttestation, Validator},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for Validator {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            (
                "withdrawal_credentials",
                self.withdrawal_credentials.to_json(),
            ),
            ("effective_balance", self.effective_balance.to_json()),
            ("slashed", self.slashed.to_json()),
            (
                "activation_eligibility_epoch",
                self.activation_eligibility_epoch.to_json(),
            ),
            ("activation_epoch", self.activation_epoch.to_json()),
            ("exit_epoch", self.exit_epoch.to_json()),
            ("withdrawable_epoch", self.withdrawable_epoch.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            withdrawal_credentials: fields.required("withdrawal_credentials")?,
            effective_balance: fields.required("effective_balance")?,
            slashed: fields.required("slashed")?,
            activation_eligibility_epoch: fields.required("activation_eligibility_epoch")?,
            activation_epoch: fields.required("activation_epoch")?,
            exit_epoch: fields.required("exit_epoch")?,
            withdrawable_epoch: fields.required("withdrawable_epoch")?,
        })
    }
}

impl<P: Preset> ApiJson for PendingAttestation<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("data", self.data.to_json()),
            ("inclusion_delay", self.inclusion_delay.to_json()),
            ("proposer_index", self.proposer_index.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            aggregation_bits: fields.required("aggregation_bits")?,
            data: fields.required("data")?,
            inclusion_delay: fields.required("inclusion_delay")?,
            proposer_index: fields.required("proposer_index")?,
        })
    }
}

impl<P: Preset> ApiJson for HistoricalBatch<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("block_roots", self.block_roots.to_json()),
            ("state_roots", self.state_roots.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            block_roots: fields.required("block_roots")?,
            state_roots: fields.required("state_roots")?,
        })
    }
}

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
                "previous_epoch_attestations",
                self.previous_epoch_attestations.to_json(),
            ),
            (
                "current_epoch_attestations",
                self.current_epoch_attestations.to_json(),
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
            previous_epoch_attestations: fields.required("previous_epoch_attestations")?,
            current_epoch_attestations: fields.required("current_epoch_attestations")?,
            justification_bits: fields.required("justification_bits")?,
            previous_justified_checkpoint: fields.required("previous_justified_checkpoint")?,
            current_justified_checkpoint: fields.required("current_justified_checkpoint")?,
            finalized_checkpoint: fields.required("finalized_checkpoint")?,
        })
    }
}
