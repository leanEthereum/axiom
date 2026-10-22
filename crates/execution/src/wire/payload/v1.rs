//! ExecutionPayloadV1, defined in `src/engine/paris.md`, the Bellatrix payload.

use axiom_json::Json;
use axiom_types::{Preset, bellatrix::ExecutionPayload};

use crate::{
    WireError,
    wire::{Fields, JsonCodec},
};

impl<P: Preset> JsonCodec for ExecutionPayload<P> {
    fn to_json(&self) -> Json {
        Json::from([
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
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
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
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::wire::payload::tests::payload_v1;

    proptest! {
        #[test]
        fn payload_v1_round_trip(payload in payload_v1()) {
            // Through the JSON value and through its text: both come back unchanged.
            let value = payload.to_json();
            prop_assert_eq!(ExecutionPayload::<Minimal>::from_json(&value), Ok(payload.clone()));
            let reparsed = Json::parse(value.to_string()).unwrap();
            prop_assert_eq!(ExecutionPayload::<Minimal>::from_json(&reparsed), Ok(payload));
        }
    }
}
