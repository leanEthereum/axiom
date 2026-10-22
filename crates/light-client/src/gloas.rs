//! Gloas's light client data, whose headers carry only the execution block hash.
//!
//! The block body holds a bid instead of a payload, see EIP-7732.
//! The state and body became progressive, which moved every proof, see EIP-7688.
//! See the Gloas light client sync protocol, fork logic, and full node spec.

use axiom_ssz::{MerkleProof, Root, Ssz};
use axiom_types::{
    Bytes32, ForkName, Hash32, Preset, Slot, capella, deneb,
    gloas::{
        self, ExecutionBranch, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
        LightClientOptimisticUpdate, LightClientUpdate,
    },
    phase0::BeaconBlockHeader,
};

use crate::{
    BootstrapData, Electra, Execution, Header, LightClientBlock, LightClientError, LightClientFork,
    UpdateData, Upgrade, branch::Branch, deneb::capella_execution,
    layout::EXECUTION_PAYLOAD_GINDEX,
};

/// The Gloas light client format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gloas;

impl<P: Preset> Header<P> for LightClientHeader {
    fn beacon(&self) -> &BeaconBlockHeader {
        &self.beacon
    }

    /// The branch proves the block hash where the block's fork kept it in the body.
    ///
    /// Before Capella there is no execution data, so the hash and branch stay zero.
    fn is_valid(&self, execution: Execution) -> bool {
        match execution.block_hash_gindex() {
            None => {
                self.execution_block_hash == Hash32::default()
                    && self
                        .execution_branch
                        .iter()
                        .all(|node| *node == Bytes32::ZERO)
            }
            Some(gindex) => Branch::new(&self.execution_branch, gindex)
                .reaches(Root(self.execution_block_hash.0), self.beacon.body_root),
        }
    }

    /// Before Gloas, the payload header's root is rebuilt from the hash and the inner branch.
    ///
    /// The branch runs from the block hash up through the payload header, then up the body.
    /// Dropping the body's part leaves the path from the hash to the payload header's root.
    fn execution_root(&self, execution: Execution) -> Root {
        let Some(gindex) = execution.payload_block_hash_gindex() else {
            return match execution {
                Execution::Bid => Root(self.execution_block_hash.0),
                Execution::Absent | Execution::Capella | Execution::Deneb => Root::ZERO,
            };
        };
        // The genesis block carries an empty payload header, which no branch describes.
        if self.beacon.slot == Slot::GENESIS {
            return match execution {
                Execution::Capella => {
                    capella::ExecutionPayloadHeader::<P>::default().hash_tree_root()
                }
                Execution::Absent | Execution::Deneb | Execution::Bid => {
                    deneb::ExecutionPayloadHeader::<P>::default().hash_tree_root()
                }
            };
        }
        let outer = EXECUTION_PAYLOAD_GINDEX.depth() as usize;
        let inner = &self.execution_branch[..self.execution_branch.len() - outer];
        let path = &inner[inner.len() - gindex.depth() as usize..];
        MerkleProof {
            branch: path.iter().map(|node| Root(node.0)).collect(),
        }
        .compute_root(Root(self.execution_block_hash.0), gindex)
        .unwrap_or(Root::ZERO)
    }
}

impl LightClientFork for Gloas {
    const FORK: ForkName = ForkName::Gloas;

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

impl Upgrade for Gloas {
    type Previous = Electra;

    /// The payload header shrinks to its block hash, whose branch grows by the inner path.
    ///
    /// See `upgrade_lc_header_to_gloas` in the Gloas light client fork logic.
    fn upgrade_header<P: Preset>(
        pre: deneb::LightClientHeader<P>,
        execution: Execution,
    ) -> LightClientHeader {
        if pre == deneb::LightClientHeader::default() {
            return LightClientHeader::default();
        }
        // The path from the block hash to the payload header's root, in the block's own shape.
        let inner = match execution {
            Execution::Absent => {
                return LightClientHeader {
                    beacon: pre.beacon,
                    execution_block_hash: Hash32::default(),
                    execution_branch: ExecutionBranch::default(),
                };
            }
            Execution::Capella => Execution::Capella
                .payload_block_hash_gindex()
                .and_then(|gindex| capella_execution(&pre.execution).prove(gindex)),
            Execution::Deneb | Execution::Bid => Execution::Deneb
                .payload_block_hash_gindex()
                .and_then(|gindex| pre.execution.prove(gindex)),
        };
        let mut nodes = inner
            .map(|(_, proof)| Branch::nodes_of(&proof))
            .unwrap_or_default();
        nodes.extend_from_slice(&pre.execution_branch);
        LightClientHeader {
            beacon: pre.beacon,
            execution_block_hash: pre.execution.block_hash,
            // Invariant: the inner path and the body path are 5 and 4 nodes, within the 11 held.
            execution_branch: Branch::pad(&nodes).unwrap_or_default(),
        }
    }
}

impl<P: Preset> LightClientBlock<P> for gloas::BeaconBlock<P> {
    type Fork = Gloas;

    /// The bid's parent block hash, proven into the body.
    ///
    /// See `block_to_light_client_header` in the Gloas light client full node spec.
    fn light_client_header(&self) -> LightClientHeader {
        let nodes = Execution::Bid
            .block_hash_gindex()
            .and_then(|gindex| self.body.prove(gindex))
            .map(|(_, proof)| Branch::nodes_of(&proof))
            .unwrap_or_default();
        LightClientHeader {
            beacon: self.header(),
            execution_block_hash: self
                .body
                .signed_execution_payload_bid
                .message
                .parent_block_hash,
            // Invariant: index 2856 sits eleven levels deep, the branch's fixed length.
            execution_branch: Branch::pad(&nodes).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, altair};

    use super::*;
    use crate::{Capella, Deneb};

    #[test]
    fn upgrading_a_deneb_header_keeps_its_validity_and_execution_root() {
        // Fixture state: the Deneb header of a block at slot 9, proving its payload.
        let mut block = deneb::BeaconBlock::<Minimal> {
            slot: Slot(9),
            ..Default::default()
        };
        block.body.execution_payload.block_hash = Hash32([5; 32]);
        block.body.execution_payload.blob_gas_used = 131_072;
        let deneb = block.light_client_header();
        assert!(Header::<Minimal>::is_valid(&deneb, Execution::Deneb));

        // The Gloas header keeps the block hash, and proves it through the payload header.
        let gloas = Gloas::upgrade_header::<Minimal>(deneb.clone(), Execution::Deneb);
        assert_eq!(gloas.execution_block_hash, Hash32([5; 32]));
        assert!(Header::<Minimal>::is_valid(&gloas, Execution::Deneb));
        assert_eq!(
            Header::<Minimal>::execution_root(&gloas, Execution::Deneb),
            Header::<Minimal>::execution_root(&deneb, Execution::Deneb)
        );

        // Mutation: another block hash no longer proves into the same body.
        let forged = LightClientHeader {
            execution_block_hash: Hash32([6; 32]),
            ..gloas
        };
        assert!(!Header::<Minimal>::is_valid(&forged, Execution::Deneb));
    }

    #[test]
    fn a_capella_header_upgrades_through_every_format_to_the_same_root() {
        // Fixture state: a Capella block at slot 9 with a block hash of all 5s.
        let mut block = capella::BeaconBlock::<Minimal> {
            slot: Slot(9),
            ..Default::default()
        };
        block.body.execution_payload.block_hash = Hash32([5; 32]);
        let capella = block.light_client_header();
        let root = Header::<Minimal>::execution_root(&capella, Execution::Capella);

        // Deneb zeroes the blob gas fields; the root still covers the Capella fields only.
        let deneb = Deneb::upgrade_header(capella, Execution::Capella);
        assert!(Header::<Minimal>::is_valid(&deneb, Execution::Capella));
        assert_eq!(
            Header::<Minimal>::execution_root(&deneb, Execution::Capella),
            root
        );

        // Gloas rebuilds that root from the block hash and the Capella-depth inner branch.
        let gloas = Gloas::upgrade_header::<Minimal>(deneb, Execution::Capella);
        assert!(Header::<Minimal>::is_valid(&gloas, Execution::Capella));
        assert_eq!(
            Header::<Minimal>::execution_root(&gloas, Execution::Capella),
            root
        );
    }

    #[test]
    fn headers_before_capella_carry_no_execution_data() {
        // Fixture state: an Altair header of a block at slot 3.
        let mut altair = altair::LightClientHeader::default();
        altair.beacon.slot = Slot(3);

        // Every later format carries empty execution data for it.
        let capella = Capella::upgrade_header::<Minimal>(altair, Execution::Absent);
        let deneb = Deneb::upgrade_header(capella, Execution::Absent);
        let gloas = Gloas::upgrade_header::<Minimal>(deneb, Execution::Absent);
        assert_eq!(gloas.execution_block_hash, Hash32::default());
        assert!(Header::<Minimal>::is_valid(&gloas, Execution::Absent));
        assert_eq!(
            Header::<Minimal>::execution_root(&gloas, Execution::Absent),
            Root::ZERO
        );
    }
}
