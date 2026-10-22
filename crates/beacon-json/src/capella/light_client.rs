//! Light client data in the Capella format, from the Capella light client spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    capella::{
        LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
        LightClientOptimisticUpdate, LightClientUpdate,
    },
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl<P: Preset> ApiJson for LightClientHeader<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("beacon", self.beacon.to_json()),
            ("execution", self.execution.to_json()),
            ("execution_branch", self.execution_branch.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            beacon: fields.required("beacon")?,
            execution: fields.required("execution")?,
            execution_branch: fields.required("execution_branch")?,
        })
    }
}

impl<P: Preset> ApiJson for LightClientBootstrap<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("header", self.header.to_json()),
            (
                "current_sync_committee",
                self.current_sync_committee.to_json(),
            ),
            (
                "current_sync_committee_branch",
                self.current_sync_committee_branch.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            header: fields.required("header")?,
            current_sync_committee: fields.required("current_sync_committee")?,
            current_sync_committee_branch: fields.required("current_sync_committee_branch")?,
        })
    }
}

impl<P: Preset> ApiJson for LightClientUpdate<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("attested_header", self.attested_header.to_json()),
            ("next_sync_committee", self.next_sync_committee.to_json()),
            (
                "next_sync_committee_branch",
                self.next_sync_committee_branch.to_json(),
            ),
            ("finalized_header", self.finalized_header.to_json()),
            ("finality_branch", self.finality_branch.to_json()),
            ("sync_aggregate", self.sync_aggregate.to_json()),
            ("signature_slot", self.signature_slot.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            attested_header: fields.required("attested_header")?,
            next_sync_committee: fields.required("next_sync_committee")?,
            next_sync_committee_branch: fields.required("next_sync_committee_branch")?,
            finalized_header: fields.required("finalized_header")?,
            finality_branch: fields.required("finality_branch")?,
            sync_aggregate: fields.required("sync_aggregate")?,
            signature_slot: fields.required("signature_slot")?,
        })
    }
}

impl<P: Preset> ApiJson for LightClientFinalityUpdate<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("attested_header", self.attested_header.to_json()),
            ("finalized_header", self.finalized_header.to_json()),
            ("finality_branch", self.finality_branch.to_json()),
            ("sync_aggregate", self.sync_aggregate.to_json()),
            ("signature_slot", self.signature_slot.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            attested_header: fields.required("attested_header")?,
            finalized_header: fields.required("finalized_header")?,
            finality_branch: fields.required("finality_branch")?,
            sync_aggregate: fields.required("sync_aggregate")?,
            signature_slot: fields.required("signature_slot")?,
        })
    }
}

impl<P: Preset> ApiJson for LightClientOptimisticUpdate<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("attested_header", self.attested_header.to_json()),
            ("sync_aggregate", self.sync_aggregate.to_json()),
            ("signature_slot", self.signature_slot.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            attested_header: fields.required("attested_header")?,
            sync_aggregate: fields.required("sync_aggregate")?,
            signature_slot: fields.required("signature_slot")?,
        })
    }
}
