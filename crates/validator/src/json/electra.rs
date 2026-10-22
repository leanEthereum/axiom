//! Electra containers in JSON: attestations across committees.

use axiom_json::Json;
use axiom_types::{
    Preset,
    electra::{AggregateAndProof, Attestation, SignedAggregateAndProof, SingleAttestation},
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

impl ApiJson for SingleAttestation {
    fn to_json(&self) -> Json {
        Json::from([
            ("committee_index", self.committee_index.to_json()),
            ("attester_index", self.attester_index.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            committee_index: fields.get("committee_index")?,
            attester_index: fields.get("attester_index")?,
            data: fields.get("data")?,
            signature: fields.get("signature")?,
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
