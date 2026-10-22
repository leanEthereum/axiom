//! Deneb's light client data, whose headers carry the Deneb payload header.
//!
//! Electra keeps this header and changes only the state branches around it.
//! See the Deneb light client sync protocol, fork logic, and full node spec.

use axiom_ssz::{Root, Ssz};
use axiom_types::{
    Bytes32, ForkName, Preset, capella,
    deneb::{
        self, ExecutionPayload, ExecutionPayloadHeader, LightClientBootstrap,
        LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate,
        LightClientUpdate,
    },
    phase0::BeaconBlockHeader,
};

use crate::{
    BootstrapData, Capella, Execution, Header, LightClientBlock, LightClientError, LightClientFork,
    UpdateData, Upgrade, branch::Branch, layout::EXECUTION_PAYLOAD_GINDEX,
};

/// The Deneb light client format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deneb;

impl<P: Preset> Header<P> for LightClientHeader<P> {
    fn beacon(&self) -> &BeaconBlockHeader {
        &self.beacon
    }

    /// The blob gas fields stay zero for a block from before Deneb, which had none.
    fn is_valid(&self, execution: Execution) -> bool {
        let blob_gas_free =
            self.execution.blob_gas_used == 0 && self.execution.excess_blob_gas == 0;
        match execution {
            Execution::Absent => {
                self.execution == ExecutionPayloadHeader::default()
                    && self
                        .execution_branch
                        .iter()
                        .all(|node| *node == Bytes32::ZERO)
            }
            Execution::Capella => blob_gas_free && proves_payload(self, execution),
            Execution::Deneb | Execution::Bid => proves_payload(self, execution),
        }
    }

    /// A block from Capella committed to a payload header without the two blob gas fields.
    fn execution_root(&self, execution: Execution) -> Root {
        match execution {
            Execution::Absent => Root::ZERO,
            Execution::Capella => capella_execution(&self.execution).hash_tree_root(),
            Execution::Deneb | Execution::Bid => self.execution.hash_tree_root(),
        }
    }
}

impl LightClientFork for Deneb {
    const FORK: ForkName = ForkName::Deneb;

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

impl Upgrade for Deneb {
    type Previous = Capella;

    /// A Capella header gains zero blob gas fields.
    ///
    /// See `upgrade_lc_header_to_deneb` in the Deneb light client fork logic.
    fn upgrade_header<P: Preset>(
        pre: capella::LightClientHeader<P>,
        _execution: Execution,
    ) -> LightClientHeader<P> {
        let execution = pre.execution;
        LightClientHeader {
            beacon: pre.beacon,
            execution: ExecutionPayloadHeader {
                parent_hash: execution.parent_hash,
                fee_recipient: execution.fee_recipient,
                state_root: execution.state_root,
                receipts_root: execution.receipts_root,
                logs_bloom: execution.logs_bloom,
                prev_randao: execution.prev_randao,
                block_number: execution.block_number,
                gas_limit: execution.gas_limit,
                gas_used: execution.gas_used,
                timestamp: execution.timestamp,
                extra_data: execution.extra_data,
                base_fee_per_gas: execution.base_fee_per_gas,
                block_hash: execution.block_hash,
                transactions_root: execution.transactions_root,
                withdrawals_root: execution.withdrawals_root,
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            execution_branch: pre.execution_branch,
        }
    }
}

impl<P: Preset> LightClientBlock<P> for deneb::BeaconBlock<P> {
    type Fork = Deneb;

    /// See `block_to_light_client_header` in the Deneb light client full node spec.
    fn light_client_header(&self) -> LightClientHeader<P> {
        payload_light_client_header(self.header(), &self.body.execution_payload, &self.body)
    }
}

/// A light client header for a block holding a Deneb payload, Deneb through Fulu.
pub(crate) fn payload_light_client_header<P: Preset, B: Ssz>(
    beacon: BeaconBlockHeader,
    payload: &ExecutionPayload<P>,
    body: &B,
) -> LightClientHeader<P> {
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
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    };
    LightClientHeader {
        beacon,
        execution,
        // Invariant: index 25 sits four levels deep, the branch's fixed length, so padding never fails.
        execution_branch: Branch::pad(&Execution::Deneb.payload_proof(body)).unwrap_or_default(),
    }
}

/// Whether a header's branch carries its execution root, in the block's shape, to the body root.
///
/// Deneb kept the payload at Capella's place in the body.
fn proves_payload<P: Preset>(header: &LightClientHeader<P>, execution: Execution) -> bool {
    Branch::new(&header.execution_branch, EXECUTION_PAYLOAD_GINDEX)
        .reaches(header.execution_root(execution), header.beacon.body_root)
}

/// A Deneb payload header as Capella defined it, without the two blob gas fields.
///
/// See `get_lc_execution_root` in the Deneb light client sync protocol.
pub(crate) fn capella_execution<P: Preset>(
    execution: &ExecutionPayloadHeader<P>,
) -> capella::ExecutionPayloadHeader<P> {
    capella::ExecutionPayloadHeader {
        parent_hash: execution.parent_hash,
        fee_recipient: execution.fee_recipient,
        state_root: execution.state_root,
        receipts_root: execution.receipts_root,
        logs_bloom: execution.logs_bloom.clone(),
        prev_randao: execution.prev_randao,
        block_number: execution.block_number,
        gas_limit: execution.gas_limit,
        gas_used: execution.gas_used,
        timestamp: execution.timestamp,
        extra_data: execution.extra_data.clone(),
        base_fee_per_gas: execution.base_fee_per_gas,
        block_hash: execution.block_hash,
        transactions_root: execution.transactions_root,
        withdrawals_root: execution.withdrawals_root,
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn blob_gas_marks_a_header_as_too_new_for_a_capella_block() {
        // Fixture state: the header of a Capella block, carried in the Deneb format.
        let mut block = capella::BeaconBlock::<Minimal>::default();
        block.body.execution_payload.block_number = 12;
        let header = Deneb::upgrade_header(block.light_client_header(), Execution::Capella);
        assert!(Header::<Minimal>::is_valid(&header, Execution::Capella));

        // Mutation: blob gas the block could not have had.
        let mut forged = header;
        forged.execution.excess_blob_gas = 1;
        assert!(!Header::<Minimal>::is_valid(&forged, Execution::Capella));
    }

    #[test]
    fn a_header_before_capella_must_be_empty() {
        // The empty header is the only valid one for a block without execution data.
        let empty = LightClientHeader::<Minimal>::default();
        assert!(Header::<Minimal>::is_valid(&empty, Execution::Absent));
        assert_eq!(
            Header::<Minimal>::execution_root(&empty, Execution::Absent),
            Root::ZERO
        );

        // Mutation: one execution field set.
        let mut forged = empty;
        forged.execution.block_number = 1;
        assert!(!Header::<Minimal>::is_valid(&forged, Execution::Absent));
    }
}
