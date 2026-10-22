//! Bellatrix containers in JSON: builder registrations.

use axiom_json::Json;
use axiom_types::bellatrix::{SignedValidatorRegistrationV1, ValidatorRegistrationV1};

use crate::json::{ApiJson, Fields, JsonError};

impl ApiJson for ValidatorRegistrationV1 {
    fn to_json(&self) -> Json {
        Json::from([
            ("fee_recipient", self.fee_recipient.to_json()),
            ("gas_limit", self.gas_limit.to_json()),
            ("timestamp", self.timestamp.to_json()),
            ("pubkey", self.pubkey.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            fee_recipient: fields.get("fee_recipient")?,
            gas_limit: fields.get("gas_limit")?,
            timestamp: fields.get("timestamp")?,
            pubkey: fields.get("pubkey")?,
        })
    }
}

impl ApiJson for SignedValidatorRegistrationV1 {
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
