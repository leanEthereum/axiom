//! The builder's bid for a slot's payload, from the Gloas beacon chain spec.

use axiom_json::Json;
use axiom_types::gloas::{ExecutionPayloadBid, SignedExecutionPayloadBid};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for ExecutionPayloadBid {
    fn to_json(&self) -> Json {
        Json::from([
            ("parent_block_hash", self.parent_block_hash.to_json()),
            ("parent_block_root", self.parent_block_root.to_json()),
            ("block_hash", self.block_hash.to_json()),
            ("prev_randao", self.prev_randao.to_json()),
            ("fee_recipient", self.fee_recipient.to_json()),
            ("gas_limit", self.gas_limit.to_json()),
            ("builder_index", self.builder_index.to_json()),
            ("slot", self.slot.to_json()),
            ("value", self.value.to_json()),
            ("execution_payment", self.execution_payment.to_json()),
            ("blob_kzg_commitments", self.blob_kzg_commitments.to_json()),
            (
                "execution_requests_root",
                self.execution_requests_root.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            parent_block_hash: fields.required("parent_block_hash")?,
            parent_block_root: fields.required("parent_block_root")?,
            block_hash: fields.required("block_hash")?,
            prev_randao: fields.required("prev_randao")?,
            fee_recipient: fields.required("fee_recipient")?,
            gas_limit: fields.required("gas_limit")?,
            builder_index: fields.required("builder_index")?,
            slot: fields.required("slot")?,
            value: fields.required("value")?,
            execution_payment: fields.required("execution_payment")?,
            blob_kzg_commitments: fields.required("blob_kzg_commitments")?,
            execution_requests_root: fields.required("execution_requests_root")?,
        })
    }
}

impl ApiJson for SignedExecutionPayloadBid {
    fn to_json(&self) -> Json {
        Json::from([
            ("message", self.message.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            message: fields.required("message")?,
            signature: fields.required("signature")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for ExecutionPayloadBid {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                parent_block_hash: sampler.draw(),
                parent_block_root: sampler.draw(),
                block_hash: sampler.draw(),
                prev_randao: sampler.draw(),
                fee_recipient: sampler.draw(),
                gas_limit: sampler.draw(),
                builder_index: sampler.draw(),
                slot: sampler.draw(),
                value: sampler.draw(),
                execution_payment: sampler.draw(),
                blob_kzg_commitments: sampler.draw(),
                execution_requests_root: sampler.draw(),
            }
        }
    }

    impl Sample for SignedExecutionPayloadBid {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn bids_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<ExecutionPayloadBid>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedExecutionPayloadBid>().map_err(TestCaseError::fail)?;
        }
    }
}
