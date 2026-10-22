//! The beacon state with its builders, from the Gloas beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    gloas::{BeaconState, Builder, BuilderPendingPayment, BuilderPendingWithdrawal},
};

use crate::{
    ApiJson, ApiJsonError,
    reader::{Fields, Reader},
};

impl ApiJson for Builder {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            ("version", Json::String(self.version.to_string())),
            ("execution_address", self.execution_address.to_json()),
            ("balance", self.balance.to_json()),
            ("deposit_epoch", self.deposit_epoch.to_json()),
            ("withdrawable_epoch", self.withdrawable_epoch.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            version: fields.read("version", Reader::u8)?,
            execution_address: fields.required("execution_address")?,
            balance: fields.required("balance")?,
            deposit_epoch: fields.required("deposit_epoch")?,
            withdrawable_epoch: fields.required("withdrawable_epoch")?,
        })
    }
}

impl ApiJson for BuilderPendingPayment {
    fn to_json(&self) -> Json {
        Json::from([
            ("weight", self.weight.to_json()),
            ("withdrawal", self.withdrawal.to_json()),
            ("proposer_index", self.proposer_index.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            weight: fields.required("weight")?,
            withdrawal: fields.required("withdrawal")?,
            proposer_index: fields.required("proposer_index")?,
        })
    }
}

impl ApiJson for BuilderPendingWithdrawal {
    fn to_json(&self) -> Json {
        Json::from([
            ("fee_recipient", self.fee_recipient.to_json()),
            ("amount", self.amount.to_json()),
            ("builder_index", self.builder_index.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            fee_recipient: fields.required("fee_recipient")?,
            amount: fields.required("amount")?,
            builder_index: fields.required("builder_index")?,
        })
    }
}

impl<P: Preset> ApiJson for BeaconState<P> {
    #[expect(
        clippy::too_many_lines,
        reason = "one line per field of the largest state"
    )]
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
            ("latest_block_hash", self.latest_block_hash.to_json()),
            (
                "next_withdrawal_index",
                self.next_withdrawal_index.to_json(),
            ),
            (
                "next_withdrawal_validator_index",
                self.next_withdrawal_validator_index.to_json(),
            ),
            ("historical_summaries", self.historical_summaries.to_json()),
            (
                "deposit_requests_start_index",
                self.deposit_requests_start_index.to_json(),
            ),
            (
                "deposit_balance_to_consume",
                self.deposit_balance_to_consume.to_json(),
            ),
            (
                "exit_balance_to_consume",
                self.exit_balance_to_consume.to_json(),
            ),
            ("earliest_exit_epoch", self.earliest_exit_epoch.to_json()),
            (
                "consolidation_balance_to_consume",
                self.consolidation_balance_to_consume.to_json(),
            ),
            (
                "earliest_consolidation_epoch",
                self.earliest_consolidation_epoch.to_json(),
            ),
            ("pending_deposits", self.pending_deposits.to_json()),
            (
                "pending_partial_withdrawals",
                self.pending_partial_withdrawals.to_json(),
            ),
            (
                "pending_consolidations",
                self.pending_consolidations.to_json(),
            ),
            ("proposer_lookahead", self.proposer_lookahead.to_json()),
            ("builders", self.builders.to_json()),
            (
                "next_withdrawal_builder_index",
                self.next_withdrawal_builder_index.to_json(),
            ),
            (
                "execution_payload_availability",
                self.execution_payload_availability.to_json(),
            ),
            (
                "builder_pending_payments",
                self.builder_pending_payments.to_json(),
            ),
            (
                "builder_pending_withdrawals",
                self.builder_pending_withdrawals.to_json(),
            ),
            (
                "latest_execution_payload_bid",
                self.latest_execution_payload_bid.to_json(),
            ),
            (
                "payload_expected_withdrawals",
                self.payload_expected_withdrawals.to_json(),
            ),
            ("ptc_window", self.ptc_window.to_json()),
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
            latest_block_hash: fields.required("latest_block_hash")?,
            next_withdrawal_index: fields.required("next_withdrawal_index")?,
            next_withdrawal_validator_index: fields.required("next_withdrawal_validator_index")?,
            historical_summaries: fields.required("historical_summaries")?,
            deposit_requests_start_index: fields.required("deposit_requests_start_index")?,
            deposit_balance_to_consume: fields.required("deposit_balance_to_consume")?,
            exit_balance_to_consume: fields.required("exit_balance_to_consume")?,
            earliest_exit_epoch: fields.required("earliest_exit_epoch")?,
            consolidation_balance_to_consume: fields
                .required("consolidation_balance_to_consume")?,
            earliest_consolidation_epoch: fields.required("earliest_consolidation_epoch")?,
            pending_deposits: fields.required("pending_deposits")?,
            pending_partial_withdrawals: fields.required("pending_partial_withdrawals")?,
            pending_consolidations: fields.required("pending_consolidations")?,
            proposer_lookahead: fields.required("proposer_lookahead")?,
            builders: fields.required("builders")?,
            next_withdrawal_builder_index: fields.required("next_withdrawal_builder_index")?,
            execution_payload_availability: fields.required("execution_payload_availability")?,
            builder_pending_payments: fields.required("builder_pending_payments")?,
            builder_pending_withdrawals: fields.required("builder_pending_withdrawals")?,
            latest_execution_payload_bid: fields.required("latest_execution_payload_bid")?,
            payload_expected_withdrawals: fields.required("payload_expected_withdrawals")?,
            ptc_window: fields.required("ptc_window")?,
        })
    }
}
