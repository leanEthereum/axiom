//! Capella's light client data, whose headers carry the execution payload header.
//!
//! See the Capella light client sync protocol, fork logic, and full node spec.

use axiom_ssz::{Root, Ssz};
use axiom_types::{
    Bytes32, ForkName, Preset, altair,
    capella::{
        self, ExecutionBranch, ExecutionPayloadHeader, LightClientBootstrap,
        LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate,
        LightClientUpdate,
    },
    phase0::BeaconBlockHeader,
};

use crate::{
    Altair, BootstrapData, Execution, Header, LightClientBlock, LightClientError, LightClientFork,
    UpdateData, Upgrade, branch::Branch,
};

/// The Capella light client format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capella;

impl<P: Preset> Header<P> for LightClientHeader<P> {
    fn beacon(&self) -> &BeaconBlockHeader {
        &self.beacon
    }

    /// Before Capella the execution data must be empty; from Capella it must prove into the body.
    fn is_valid(&self, execution: Execution) -> bool {
        match execution.payload_gindex() {
            None => {
                self.execution == ExecutionPayloadHeader::default()
                    && self
                        .execution_branch
                        .iter()
                        .all(|node| *node == Bytes32::ZERO)
            }
            Some(gindex) => Branch::new(&self.execution_branch, gindex)
                .reaches(self.execution_root(execution), self.beacon.body_root),
        }
    }

    fn execution_root(&self, execution: Execution) -> Root {
        match execution {
            Execution::Absent => Root::ZERO,
            Execution::Capella | Execution::Deneb | Execution::Bid => {
                self.execution.hash_tree_root()
            }
        }
    }
}

impl LightClientFork for Capella {
    const FORK: ForkName = ForkName::Capella;

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

impl Upgrade for Capella {
    type Previous = Altair;

    /// An Altair header gains empty execution data.
    ///
    /// See `upgrade_lc_header_to_capella` in the Capella light client fork logic.
    fn upgrade_header<P: Preset>(
        pre: altair::LightClientHeader,
        _execution: Execution,
    ) -> LightClientHeader<P> {
        LightClientHeader {
            beacon: pre.beacon,
            execution: ExecutionPayloadHeader::default(),
            execution_branch: ExecutionBranch::default(),
        }
    }
}

impl<P: Preset> LightClientBlock<P> for capella::BeaconBlock<P> {
    type Fork = Capella;

    /// See `block_to_light_client_header` in the Capella light client full node spec.
    fn light_client_header(&self) -> LightClientHeader<P> {
        let payload = &self.body.execution_payload;
        let execution = ExecutionPayloadHeader {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.hash_tree_root(),
            withdrawals_root: payload.withdrawals.hash_tree_root(),
        };
        LightClientHeader {
            beacon: self.header(),
            execution,
            // Invariant: index 25 sits four levels deep, the branch's fixed length, so padding never fails.
            execution_branch: Branch::pad(&Execution::Capella.payload_proof(&self.body))
                .unwrap_or_default(),
        }
    }
}
