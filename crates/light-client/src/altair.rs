//! Altair's light client data, whose headers carry the beacon header alone.
//!
//! Bellatrix keeps this format: its payload stays out of light client data.
//! See the Altair light client sync protocol.

use axiom_ssz::Root;
use axiom_types::{
    ForkName, Preset,
    altair::{
        self, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
        LightClientOptimisticUpdate, LightClientUpdate,
    },
    bellatrix, phase0,
};

use crate::{
    BootstrapData, Execution, Header, LightClientBlock, LightClientError, LightClientFork,
    UpdateData, branch::Branch,
};

/// The Altair light client format, also Bellatrix's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Altair;

impl<P: Preset> Header<P> for LightClientHeader {
    fn beacon(&self) -> &phase0::BeaconBlockHeader {
        &self.beacon
    }

    /// Always valid: there is no execution data to check.
    fn is_valid(&self, _execution: Execution) -> bool {
        true
    }

    fn execution_root(&self, _execution: Execution) -> Root {
        Root::ZERO
    }
}

impl LightClientFork for Altair {
    const FORK: ForkName = ForkName::Altair;

    type Header<P: Preset> = LightClientHeader;
    type Bootstrap<P: Preset> = LightClientBootstrap<P>;
    type Update<P: Preset> = LightClientUpdate<P>;
    type FinalityUpdate<P: Preset> = LightClientFinalityUpdate<P>;
    type OptimisticUpdate<P: Preset> = LightClientOptimisticUpdate<P>;

    fn bootstrap_data<P: Preset>(
        bootstrap: LightClientBootstrap<P>,
    ) -> BootstrapData<LightClientHeader, P> {
        BootstrapData {
            header: bootstrap.header,
            current_sync_committee: bootstrap.current_sync_committee,
            current_sync_committee_branch: bootstrap.current_sync_committee_branch.into_vec(),
        }
    }

    fn bootstrap<P: Preset>(
        data: BootstrapData<LightClientHeader, P>,
    ) -> Result<LightClientBootstrap<P>, LightClientError> {
        Ok(LightClientBootstrap {
            header: data.header,
            current_sync_committee: data.current_sync_committee,
            current_sync_committee_branch: Branch::pad(&data.current_sync_committee_branch)?,
        })
    }

    fn update_data<P: Preset>(update: LightClientUpdate<P>) -> UpdateData<LightClientHeader, P> {
        UpdateData {
            attested_header: update.attested_header,
            next_sync_committee: update.next_sync_committee,
            next_sync_committee_branch: update.next_sync_committee_branch.into_vec(),
            finalized_header: update.finalized_header,
            finality_branch: update.finality_branch.into_vec(),
            sync_aggregate: update.sync_aggregate,
            signature_slot: update.signature_slot,
        }
    }

    fn update<P: Preset>(
        data: UpdateData<LightClientHeader, P>,
    ) -> Result<LightClientUpdate<P>, LightClientError> {
        Ok(LightClientUpdate {
            attested_header: data.attested_header,
            next_sync_committee: data.next_sync_committee,
            next_sync_committee_branch: Branch::pad(&data.next_sync_committee_branch)?,
            finalized_header: data.finalized_header,
            finality_branch: Branch::pad(&data.finality_branch)?,
            sync_aggregate: data.sync_aggregate,
            signature_slot: data.signature_slot,
        })
    }

    fn finality_update_data<P: Preset>(
        update: LightClientFinalityUpdate<P>,
    ) -> UpdateData<LightClientHeader, P> {
        UpdateData {
            attested_header: update.attested_header,
            next_sync_committee_branch: LightClientUpdate::<P>::default()
                .next_sync_committee_branch
                .into_vec(),
            finalized_header: update.finalized_header,
            finality_branch: update.finality_branch.into_vec(),
            sync_aggregate: update.sync_aggregate,
            signature_slot: update.signature_slot,
            ..UpdateData::default()
        }
    }

    fn finality_update<P: Preset>(
        data: UpdateData<LightClientHeader, P>,
    ) -> Result<LightClientFinalityUpdate<P>, LightClientError> {
        Ok(LightClientFinalityUpdate {
            attested_header: data.attested_header,
            finalized_header: data.finalized_header,
            finality_branch: Branch::pad(&data.finality_branch)?,
            sync_aggregate: data.sync_aggregate,
            signature_slot: data.signature_slot,
        })
    }

    fn optimistic_update_data<P: Preset>(
        update: LightClientOptimisticUpdate<P>,
    ) -> UpdateData<LightClientHeader, P> {
        let empty = LightClientUpdate::<P>::default();
        UpdateData {
            attested_header: update.attested_header,
            next_sync_committee_branch: empty.next_sync_committee_branch.into_vec(),
            finality_branch: empty.finality_branch.into_vec(),
            sync_aggregate: update.sync_aggregate,
            signature_slot: update.signature_slot,
            ..UpdateData::default()
        }
    }

    fn optimistic_update<P: Preset>(
        data: UpdateData<LightClientHeader, P>,
    ) -> LightClientOptimisticUpdate<P> {
        LightClientOptimisticUpdate {
            attested_header: data.attested_header,
            sync_aggregate: data.sync_aggregate,
            signature_slot: data.signature_slot,
        }
    }
}

impl<P: Preset> LightClientBlock<P> for phase0::BeaconBlock<P> {
    type Fork = Altair;

    /// The beacon header alone, as Altair would describe a block from before it.
    fn light_client_header(&self) -> LightClientHeader {
        LightClientHeader {
            beacon: self.header(),
        }
    }
}

impl<P: Preset> LightClientBlock<P> for altair::BeaconBlock<P> {
    type Fork = Altair;

    /// See `block_to_light_client_header` in the Altair light client full node spec.
    fn light_client_header(&self) -> LightClientHeader {
        LightClientHeader {
            beacon: self.header(),
        }
    }
}

impl<P: Preset> LightClientBlock<P> for bellatrix::BeaconBlock<P> {
    type Fork = Altair;

    /// The beacon header alone: light client data leaves the Bellatrix payload out.
    fn light_client_header(&self) -> LightClientHeader {
        LightClientHeader {
            beacon: self.header(),
        }
    }
}
