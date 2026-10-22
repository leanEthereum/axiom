//! Altair containers in JSON: the sync committee's messages.

use axiom_json::Json;
use axiom_types::{
    Preset,
    altair::{
        ContributionAndProof, SignedContributionAndProof, SyncAggregatorSelectionData,
        SyncCommitteeContribution, SyncCommitteeMessage,
    },
};

use crate::json::{ApiJson, Fields, JsonError};

impl ApiJson for SyncCommitteeMessage {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            slot: fields.get("slot")?,
            beacon_block_root: fields.get("beacon_block_root")?,
            validator_index: fields.get("validator_index")?,
            signature: fields.get("signature")?,
        })
    }
}

impl<P: Preset> ApiJson for SyncCommitteeContribution<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("beacon_block_root", self.beacon_block_root.to_json()),
            ("subcommittee_index", self.subcommittee_index.to_json()),
            ("aggregation_bits", self.aggregation_bits.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            slot: fields.get("slot")?,
            beacon_block_root: fields.get("beacon_block_root")?,
            subcommittee_index: fields.get("subcommittee_index")?,
            aggregation_bits: fields.get("aggregation_bits")?,
            signature: fields.get("signature")?,
        })
    }
}

impl<P: Preset> ApiJson for ContributionAndProof<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("aggregator_index", self.aggregator_index.to_json()),
            ("contribution", self.contribution.to_json()),
            ("selection_proof", self.selection_proof.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            aggregator_index: fields.get("aggregator_index")?,
            contribution: fields.get("contribution")?,
            selection_proof: fields.get("selection_proof")?,
        })
    }
}

impl<P: Preset> ApiJson for SignedContributionAndProof<P> {
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

impl ApiJson for SyncAggregatorSelectionData {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("subcommittee_index", self.subcommittee_index.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            slot: fields.get("slot")?,
            subcommittee_index: fields.get("subcommittee_index")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsSignature, Minimal, Root, Slot, ValidatorIndex};

    use super::*;

    #[test]
    fn a_signed_contribution_round_trips() {
        // Fixture state: subcommittee 2 at slot 9, with seats 0 and 3 of 8 signing.
        let mut contribution = SyncCommitteeContribution::<Minimal> {
            slot: Slot(9),
            beacon_block_root: Root([4; 32]),
            subcommittee_index: 2,
            signature: BlsSignature([5; 96]),
            ..SyncCommitteeContribution::default()
        };
        contribution.aggregation_bits.set(0, true);
        contribution.aggregation_bits.set(3, true);
        let signed = SignedContributionAndProof {
            message: ContributionAndProof {
                aggregator_index: ValidatorIndex(17),
                contribution,
                selection_proof: BlsSignature([6; 96]),
            },
            signature: BlsSignature([7; 96]),
        };

        // Bits 0 and 3 set is the byte 0x09.
        let json = signed.to_json();
        assert_eq!(
            json.get("message")
                .and_then(|message| message.get("contribution"))
                .and_then(|contribution| contribution.get("aggregation_bits")),
            Some(&Json::from("0x09"))
        );
        assert_eq!(SignedContributionAndProof::from_json(&json), Ok(signed));
    }
}
