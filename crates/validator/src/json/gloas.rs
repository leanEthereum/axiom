//! Gloas containers in JSON: payload timeliness votes, preferences, and attestations.

use axiom_json::Json;
use axiom_types::{
    Preset,
    gloas::{
        AggregateAndProof, Attestation, PayloadAttestationData, PayloadAttestationMessage,
        ProposerPreferences, SignedAggregateAndProof, SignedProposerPreferences,
    },
};

use crate::json::{ApiJson, Fields, JsonError};

impl<P: Preset> ApiJson for Attestation<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
            ("committee_bits", self.committee_bits.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            aggregation_bits: fields.get("aggregation_bits")?,
            data: fields.get("data")?,
            signature: fields.get("signature")?,
            committee_bits: fields.get("committee_bits")?,
        })
    }
}

impl<P: Preset> ApiJson for AggregateAndProof<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregator_index", self.aggregator_index.to_json()),
            ("aggregate", self.aggregate.to_json()),
            ("selection_proof", self.selection_proof.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            aggregator_index: fields.get("aggregator_index")?,
            aggregate: fields.get("aggregate")?,
            selection_proof: fields.get("selection_proof")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedAggregateAndProof<P> {
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

impl ApiJson for PayloadAttestationData {
    fn to_json(&self) -> Json {
        Json::from([
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("slot", self.slot.to_json()),
            ("payload_present", self.payload_present.to_json()),
            ("blob_data_available", self.blob_data_available.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            beacon_block_root: fields.get("beacon_block_root")?,
            slot: fields.get("slot")?,
            payload_present: fields.get("payload_present")?,
            blob_data_available: fields.get("blob_data_available")?,
        })
    }
}

impl ApiJson for PayloadAttestationMessage {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            validator_index: fields.get("validator_index")?,
            data: fields.get("data")?,
            signature: fields.get("signature")?,
        })
    }
}

impl ApiJson for ProposerPreferences {
    fn to_json(&self) -> Json {
        Json::from([
            ("dependent_root", self.dependent_root.to_json()),
            ("proposal_slot", self.proposal_slot.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("fee_recipient", self.fee_recipient.to_json()),
            ("target_gas_limit", self.target_gas_limit.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            dependent_root: fields.get("dependent_root")?,
            proposal_slot: fields.get("proposal_slot")?,
            validator_index: fields.get("validator_index")?,
            fee_recipient: fields.get("fee_recipient")?,
            target_gas_limit: fields.get("target_gas_limit")?,
        })
    }
}

impl ApiJson for SignedProposerPreferences {
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
