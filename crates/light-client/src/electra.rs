//! Electra's light client data, whose state branches reach one level deeper.
//!
//! The header is Deneb's; the state grew past 32 fields, which lengthens every state branch.
//! Fulu keeps this format.
//! See the Electra light client sync protocol and fork logic.

use axiom_types::{
    ForkName, Preset,
    electra::{
        self, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
        LightClientOptimisticUpdate, LightClientUpdate,
    },
};

use crate::{
    BootstrapData, Deneb, Execution, LightClientBlock, LightClientError, LightClientFork,
    UpdateData, Upgrade, branch::Branch, deneb::payload_light_client_header,
};

/// The Electra light client format, also Fulu's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Electra;

impl LightClientFork for Electra {
    const FORK: ForkName = ForkName::Electra;

    type Header<P: Preset> = LightClientHeader<P>;
    type Bootstrap<P: Preset> = LightClientBootstrap<P>;
    type Update<P: Preset> = LightClientUpdate<P>;
    type FinalityUpdate<P: Preset> = LightClientFinalityUpdate<P>;
    type OptimisticUpdate<P: Preset> = LightClientOptimisticUpdate<P>;

    fn bootstrap_data<P: Preset>(
        bootstrap: LightClientBootstrap<P>,
    ) -> BootstrapData<LightClientHeader<P>, P> {
        BootstrapData {
            header: bootstrap.header,
            current_sync_committee: bootstrap.current_sync_committee,
            current_sync_committee_branch: bootstrap.current_sync_committee_branch.into_vec(),
        }
    }

    fn bootstrap<P: Preset>(
        data: BootstrapData<LightClientHeader<P>, P>,
    ) -> Result<LightClientBootstrap<P>, LightClientError> {
        Ok(LightClientBootstrap {
            header: data.header,
            current_sync_committee: data.current_sync_committee,
            current_sync_committee_branch: Branch::pad(&data.current_sync_committee_branch)?,
        })
    }

    fn update_data<P: Preset>(update: LightClientUpdate<P>) -> UpdateData<LightClientHeader<P>, P> {
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
        data: UpdateData<LightClientHeader<P>, P>,
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
    ) -> UpdateData<LightClientHeader<P>, P> {
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
        data: UpdateData<LightClientHeader<P>, P>,
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
    ) -> UpdateData<LightClientHeader<P>, P> {
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
        data: UpdateData<LightClientHeader<P>, P>,
    ) -> LightClientOptimisticUpdate<P> {
        LightClientOptimisticUpdate {
            attested_header: data.attested_header,
            sync_aggregate: data.sync_aggregate,
            signature_slot: data.signature_slot,
        }
    }
}

impl Upgrade for Electra {
    type Previous = Deneb;

    /// The header is unchanged; only the branches around it grow, padded with zeros.
    ///
    /// See `upgrade_lc_header_to_electra` in the Electra light client fork logic.
    fn upgrade_header<P: Preset>(
        pre: LightClientHeader<P>,
        _execution: Execution,
    ) -> LightClientHeader<P> {
        pre
    }
}

impl<P: Preset> LightClientBlock<P> for electra::BeaconBlock<P> {
    type Fork = Electra;

    /// Deneb's header, built the same way: Electra kept the Deneb payload.
    fn light_client_header(&self) -> LightClientHeader<P> {
        payload_light_client_header(self.header(), &self.body.execution_payload, &self.body)
    }
}
