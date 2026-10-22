//! ExecutionPayloadV2, defined in `src/engine/shanghai.md`, the Capella payload.
//!
//! It appends the withdrawals to the V1 members.

use axiom_json::Json;
use axiom_types::{Preset, capella::ExecutionPayload};

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
            ("withdrawals", self.withdrawals.to_json()),
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
            withdrawals: fields.required("withdrawals")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, bellatrix};
    use proptest::prelude::*;

    use super::*;
    use crate::{WireErrorKind, wire::payload::tests::payload_v2};

    proptest! {
        #[test]
        fn payload_v2_round_trip(payload in payload_v2()) {
            // Through the JSON value and through its text: both come back unchanged.
            let value = payload.to_json();
            prop_assert_eq!(ExecutionPayload::<Minimal>::from_json(&value), Ok(payload.clone()));
            let reparsed = Json::parse(value.to_string()).unwrap();
            prop_assert_eq!(ExecutionPayload::<Minimal>::from_json(&reparsed), Ok(payload));
        }
    }

    #[test]
    fn an_older_version_lacks_the_newer_members() {
        // A V1 payload has every member but the withdrawals, so it is no V2 payload.
        let v1 = bellatrix::ExecutionPayload::<Minimal>::default().to_json();
        assert_eq!(
            ExecutionPayload::<Minimal>::from_json(&v1),
            Err(WireError::new(WireErrorKind::Missing).in_member("withdrawals"))
        );
    }
}
