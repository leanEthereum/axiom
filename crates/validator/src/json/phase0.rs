//! Phase0 containers in JSON.

use axiom_json::Json;
use axiom_types::{
    Preset,
    phase0::{
        AggregateAndProof, Attestation, AttestationData, BeaconBlockHeader, Checkpoint,
        DepositMessage, Fork, SignedAggregateAndProof, SignedVoluntaryExit, VoluntaryExit,
    },
};

use crate::json::{ApiJson, Fields, JsonError};

impl ApiJson for Checkpoint {
    fn to_json(&self) -> Json {
        Json::from([
            ("epoch", self.epoch.to_json()),
            ("root", self.root.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            epoch: fields.get("epoch")?,
            root: fields.get("root")?,
        })
    }
}

impl ApiJson for AttestationData {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("index", self.index.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("source", self.source.to_json()),
            ("target", self.target.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            slot: fields.get("slot")?,
            index: fields.get("index")?,
            beacon_block_root: fields.get("beacon_block_root")?,
            source: fields.get("source")?,
            target: fields.get("target")?,
        })
    }
}

impl<P: Preset> ApiJson for Attestation<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("data", self.data.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            aggregation_bits: fields.get("aggregation_bits")?,
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

impl ApiJson for VoluntaryExit {
    fn to_json(&self) -> Json {
        Json::from([
            ("epoch", self.epoch.to_json()),
            ("validator_index", self.validator_index.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            epoch: fields.get("epoch")?,
            validator_index: fields.get("validator_index")?,
        })
    }
}

impl ApiJson for SignedVoluntaryExit {
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

impl ApiJson for BeaconBlockHeader {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("proposer_index", self.proposer_index.to_json()),
            ("parent_root", self.parent_root.to_json()),
            ("state_root", self.state_root.to_json()),
            ("body_root", self.body_root.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            slot: fields.get("slot")?,
            proposer_index: fields.get("proposer_index")?,
            parent_root: fields.get("parent_root")?,
            state_root: fields.get("state_root")?,
            body_root: fields.get("body_root")?,
        })
    }
}

impl ApiJson for DepositMessage {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            (
                "withdrawal_credentials",
                self.withdrawal_credentials.to_json(),
            ),
            ("amount", self.amount.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            pubkey: fields.get("pubkey")?,
            withdrawal_credentials: fields.get("withdrawal_credentials")?,
            amount: fields.get("amount")?,
        })
    }
}

impl ApiJson for Fork {
    fn to_json(&self) -> Json {
        Json::from([
            ("previous_version", self.previous_version.to_json()),
            ("current_version", self.current_version.to_json()),
            ("epoch", self.epoch.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            previous_version: fields.get("previous_version")?,
            current_version: fields.get("current_version")?,
            epoch: fields.get("epoch")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{CommitteeIndex, Epoch, Minimal, Root, Slot};

    use super::*;

    #[test]
    fn attestation_data_matches_the_beacon_api_example_shape() {
        // Fixture state: slot 1, committee 1, every root 0xcf8e...ac2, as in the beacon API's example.
        let root = "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2";
        let text = format!(
            r#"{{"slot":"1","index":"1","beacon_block_root":"{root}","source":{{"epoch":"1","root":"{root}"}},"target":{{"epoch":"1","root":"{root}"}}}}"#
        );
        let data = AttestationData::from_json(&Json::parse(&text).unwrap()).unwrap();
        let root = Root::from_json(&Json::from(root)).unwrap();
        let checkpoint = Checkpoint {
            epoch: Epoch(1),
            root,
        };
        assert_eq!(
            data,
            AttestationData {
                slot: Slot(1),
                index: CommitteeIndex(1),
                beacon_block_root: root,
                source: checkpoint,
                target: checkpoint,
            }
        );

        // Writing it back gives the same text, member order included.
        assert_eq!(data.to_json().to_string(), text);
    }

    #[test]
    fn a_bad_member_is_named_in_the_error() {
        // Mutation: the slot is a JSON number, not a decimal string.
        let json = Json::parse(r#"{"aggregation_bits":"0x01","data":{"slot":1}}"#).unwrap();
        assert_eq!(
            Attestation::<Minimal>::from_json(&json).unwrap_err(),
            JsonError::Member {
                name: "data",
                source: Box::new(JsonError::Member {
                    name: "slot",
                    source: Box::new(JsonError::Type {
                        expected: "string",
                        found: "number",
                    }),
                }),
            }
        );
    }
}
