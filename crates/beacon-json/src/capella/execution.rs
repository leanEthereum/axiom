//! Withdrawals, the payload, and its header, from the Capella beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    capella::{ExecutionPayload, ExecutionPayloadHeader, Withdrawal},
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for Withdrawal {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("address", self.address.to_json()),
            ("amount", self.amount.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            validator_index: fields.required("validator_index")?,
            address: fields.required("address")?,
            amount: fields.required("amount")?,
        })
    }
}

impl<P: Preset> ApiJson for ExecutionPayload<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("parent_hash", self.parent_hash.to_json()),
            ("fee_recipient", self.fee_recipient.to_json()),
            ("state_root", self.state_root.to_json()),
            ("receipts_root", self.receipts_root.to_json()),
            ("logs_bloom", self.logs_bloom.to_json()),
            ("prev_randao", self.prev_randao.to_json()),
            ("block_number", self.block_number.to_json()),
            ("gas_limit", self.gas_limit.to_json()),
            ("gas_used", self.gas_used.to_json()),
            ("timestamp", self.timestamp.to_json()),
            ("extra_data", self.extra_data.to_json()),
            ("base_fee_per_gas", self.base_fee_per_gas.to_json()),
            ("block_hash", self.block_hash.to_json()),
            ("transactions", self.transactions.to_json()),
            ("withdrawals", self.withdrawals.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            parent_hash: fields.required("parent_hash")?,
            fee_recipient: fields.required("fee_recipient")?,
            state_root: fields.required("state_root")?,
            receipts_root: fields.required("receipts_root")?,
            logs_bloom: fields.required("logs_bloom")?,
            prev_randao: fields.required("prev_randao")?,
            block_number: fields.required("block_number")?,
            gas_limit: fields.required("gas_limit")?,
            gas_used: fields.required("gas_used")?,
            timestamp: fields.required("timestamp")?,
            extra_data: fields.required("extra_data")?,
            base_fee_per_gas: fields.required("base_fee_per_gas")?,
            block_hash: fields.required("block_hash")?,
            transactions: fields.required("transactions")?,
            withdrawals: fields.required("withdrawals")?,
        })
    }
}

impl<P: Preset> ApiJson for ExecutionPayloadHeader<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("parent_hash", self.parent_hash.to_json()),
            ("fee_recipient", self.fee_recipient.to_json()),
            ("state_root", self.state_root.to_json()),
            ("receipts_root", self.receipts_root.to_json()),
            ("logs_bloom", self.logs_bloom.to_json()),
            ("prev_randao", self.prev_randao.to_json()),
            ("block_number", self.block_number.to_json()),
            ("gas_limit", self.gas_limit.to_json()),
            ("gas_used", self.gas_used.to_json()),
            ("timestamp", self.timestamp.to_json()),
            ("extra_data", self.extra_data.to_json()),
            ("base_fee_per_gas", self.base_fee_per_gas.to_json()),
            ("block_hash", self.block_hash.to_json()),
            ("transactions_root", self.transactions_root.to_json()),
            ("withdrawals_root", self.withdrawals_root.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            parent_hash: fields.required("parent_hash")?,
            fee_recipient: fields.required("fee_recipient")?,
            state_root: fields.required("state_root")?,
            receipts_root: fields.required("receipts_root")?,
            logs_bloom: fields.required("logs_bloom")?,
            prev_randao: fields.required("prev_randao")?,
            block_number: fields.required("block_number")?,
            gas_limit: fields.required("gas_limit")?,
            gas_used: fields.required("gas_used")?,
            timestamp: fields.required("timestamp")?,
            extra_data: fields.required("extra_data")?,
            base_fee_per_gas: fields.required("base_fee_per_gas")?,
            block_hash: fields.required("block_hash")?,
            transactions_root: fields.required("transactions_root")?,
            withdrawals_root: fields.required("withdrawals_root")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for Withdrawal {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                index: sampler.draw(),
                validator_index: sampler.draw(),
                address: sampler.draw(),
                amount: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for ExecutionPayload<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                parent_hash: sampler.draw(),
                fee_recipient: sampler.draw(),
                state_root: sampler.draw(),
                receipts_root: sampler.draw(),
                logs_bloom: sampler.draw(),
                prev_randao: sampler.draw(),
                block_number: sampler.draw(),
                gas_limit: sampler.draw(),
                gas_used: sampler.draw(),
                timestamp: sampler.draw(),
                extra_data: sampler.draw(),
                base_fee_per_gas: sampler.draw(),
                block_hash: sampler.draw(),
                transactions: sampler.draw(),
                withdrawals: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for ExecutionPayloadHeader<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                parent_hash: sampler.draw(),
                fee_recipient: sampler.draw(),
                state_root: sampler.draw(),
                receipts_root: sampler.draw(),
                logs_bloom: sampler.draw(),
                prev_randao: sampler.draw(),
                block_number: sampler.draw(),
                gas_limit: sampler.draw(),
                gas_used: sampler.draw(),
                timestamp: sampler.draw(),
                extra_data: sampler.draw(),
                base_fee_per_gas: sampler.draw(),
                block_hash: sampler.draw(),
                transactions_root: sampler.draw(),
                withdrawals_root: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn payloads_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<Withdrawal>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ExecutionPayload<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ExecutionPayloadHeader<Minimal>>().map_err(TestCaseError::fail)?;
        }
    }
}
