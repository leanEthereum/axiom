//! ExecutionPayloadV3 and WithdrawalV1.
//!
//! The payload JSON is defined in `src/engine/cancun.md`, the withdrawal in `shanghai.md`.
//! Prague and Osaka reuse ExecutionPayloadV3 unchanged.
//!
//! ```text
//!     consensus container           JSON member              encoding
//!     parent_hash                   parentHash               DATA 32
//!     fee_recipient                 feeRecipient             DATA 20
//!     state_root                    stateRoot                DATA 32
//!     receipts_root                 receiptsRoot             DATA 32
//!     logs_bloom                    logsBloom                DATA 256
//!     prev_randao                   prevRandao               DATA 32
//!     block_number                  blockNumber              QUANTITY 64
//!     gas_limit                     gasLimit                 QUANTITY 64
//!     gas_used                      gasUsed                  QUANTITY 64
//!     timestamp                     timestamp                QUANTITY 64
//!     extra_data                    extraData                DATA 0..32
//!     base_fee_per_gas              baseFeePerGas            QUANTITY 256
//!     block_hash                    blockHash                DATA 32
//!     transactions                  transactions             array of DATA
//!     withdrawals                   withdrawals              array of WithdrawalV1
//!     blob_gas_used                 blobGasUsed              QUANTITY 64
//!     excess_blob_gas               excessBlobGas            QUANTITY 64
//! ```

use axiom_json::Json;
use axiom_types::{ExecutionPayload, Preset, Withdrawal};

use super::{Fields, JsonCodec, object};
use crate::WireError;

impl JsonCodec for Withdrawal {
    /// WithdrawalV1: the amount stays in Gwei, as the consensus layer counts it.
    fn to_json(&self) -> Json {
        object([
            ("index", self.index.to_json()),
            ("validatorIndex", self.validator_index.to_json()),
            ("address", self.address.to_json()),
            ("amount", self.amount.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            validator_index: fields.required("validatorIndex")?,
            address: fields.required("address")?,
            amount: fields.required("amount")?,
        })
    }
}

impl<P: Preset> JsonCodec for ExecutionPayload<P> {
    fn to_json(&self) -> Json {
        object([
            ("parentHash", self.parent_hash.to_json()),
            ("feeRecipient", self.fee_recipient.to_json()),
            ("stateRoot", self.state_root.to_json()),
            ("receiptsRoot", self.receipts_root.to_json()),
            ("logsBloom", self.logs_bloom.to_json()),
            ("prevRandao", self.prev_randao.to_json()),
            ("blockNumber", self.block_number.to_json()),
            ("gasLimit", self.gas_limit.to_json()),
            ("gasUsed", self.gas_used.to_json()),
            ("timestamp", self.timestamp.to_json()),
            ("extraData", self.extra_data.to_json()),
            ("baseFeePerGas", self.base_fee_per_gas.to_json()),
            ("blockHash", self.block_hash.to_json()),
            ("transactions", self.transactions.to_json()),
            ("withdrawals", self.withdrawals.to_json()),
            ("blobGasUsed", self.blob_gas_used.to_json()),
            ("excessBlobGas", self.excess_blob_gas.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        // Every member is required; a V1 or V2 payload lacks the later ones and is refused.
        let fields = Fields::of(value)?;
        Ok(Self {
            parent_hash: fields.required("parentHash")?,
            fee_recipient: fields.required("feeRecipient")?,
            state_root: fields.required("stateRoot")?,
            receipts_root: fields.required("receiptsRoot")?,
            logs_bloom: fields.required("logsBloom")?,
            prev_randao: fields.required("prevRandao")?,
            block_number: fields.required("blockNumber")?,
            gas_limit: fields.required("gasLimit")?,
            gas_used: fields.required("gasUsed")?,
            timestamp: fields.required("timestamp")?,
            extra_data: fields.required("extraData")?,
            base_fee_per_gas: fields.required("baseFeePerGas")?,
            block_hash: fields.required("blockHash")?,
            transactions: fields.required("transactions")?,
            withdrawals: fields.required("withdrawals")?,
            blob_gas_used: fields.required("blobGasUsed")?,
            excess_blob_gas: fields.required("excessBlobGas")?,
        })
    }
}
