//! Capella containers in JSON: withdrawal credential changes.

use axiom_json::Json;
use axiom_types::capella::{BlsToExecutionChange, SignedBlsToExecutionChange};

use crate::json::{ApiJson, Fields, JsonError};

impl ApiJson for BlsToExecutionChange {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("from_bls_pubkey", self.from_bls_pubkey.to_json()),
            ("to_execution_address", self.to_execution_address.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            validator_index: fields.get("validator_index")?,
            from_bls_pubkey: fields.get("from_bls_pubkey")?,
            to_execution_address: fields.get("to_execution_address")?,
        })
    }
}

impl ApiJson for SignedBlsToExecutionChange {
    fn to_json(&self) -> Json {
        Json::from([
            ("message", self.message.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            message: fields.get("message")?,
            signature: fields.get("signature")?,
        })
    }
}
