//! Blob sidecars of Deneb and Electra: the subnets they travel on, and their proofs.

use axiom_kzg::{Blob, Bytes48, Kzg};
use axiom_ssz::{Container, GeneralizedIndex, Length, MerkleProof, Root, Ssz};
use axiom_types::{
    BlobIndex, ChainConfig, ForkName, Preset,
    deneb::{BeaconBlockBody, BlobSidecar},
};

/// Index of the commitment list among the fields of a block body.
///
/// Electra appends a field, which keeps the body tree at the same depth.
/// See `get_generalized_index(BeaconBlockBody, "blob_kzg_commitments")` in the Deneb p2p spec.
const BLOB_KZG_COMMITMENTS_FIELD: usize = 11;

/// How many blobs a block may carry, and how many subnets their sidecars spread over.
///
/// Electra raised both, see EIP-7691.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobSubnets {
    /// The most blobs a block may carry.
    pub max_blobs: u64,
    /// Subnets the sidecars spread over.
    pub subnet_count: u64,
}

impl BlobSubnets {
    /// The limits of Deneb.
    ///
    /// See `MAX_BLOBS_PER_BLOCK` and `BLOB_SIDECAR_SUBNET_COUNT` in the Deneb config.
    #[must_use]
    pub const fn deneb(config: &ChainConfig) -> Self {
        Self {
            max_blobs: config.max_blobs_per_block,
            subnet_count: config.blob_sidecar_subnet_count,
        }
    }

    /// The limits of Electra.
    ///
    /// See `MAX_BLOBS_PER_BLOCK_ELECTRA` and `BLOB_SIDECAR_SUBNET_COUNT_ELECTRA` in the config.
    #[must_use]
    pub const fn electra(config: &ChainConfig) -> Self {
        Self {
            max_blobs: config.max_blobs_per_block_electra,
            subnet_count: config.blob_sidecar_subnet_count_electra,
        }
    }

    /// The limits of a fork whose blobs travel as sidecars, or nothing for any other fork.
    #[must_use]
    pub const fn of(fork: ForkName, config: &ChainConfig) -> Option<Self> {
        match fork {
            ForkName::Deneb => Some(Self::deneb(config)),
            ForkName::Electra => Some(Self::electra(config)),
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Fulu
            | ForkName::Gloas
            | ForkName::Hstar => None,
        }
    }

    /// The subnet a blob's sidecar travels on.
    ///
    /// See `compute_subnet_for_blob_sidecar` in the Deneb p2p spec.
    #[must_use]
    pub const fn subnet(self, index: BlobIndex) -> u64 {
        index.0 % self.subnet_count
    }
}

/// The proofs a blob sidecar carries, checked against its header and its blob.
#[derive(Clone, Copy, Debug)]
pub struct CheckedBlob<'a, P: Preset>(pub &'a BlobSidecar<P>);

impl<P: Preset> CheckedBlob<'_, P> {
    /// Whether the commitment sits at its index in the body the header commits to.
    ///
    /// See `verify_blob_sidecar_inclusion_proof` in the Deneb p2p spec.
    #[must_use]
    pub fn has_valid_inclusion_proof(self) -> bool {
        let sidecar = self.0;
        // The list's data tree is the left child of its root, the length the right one.
        let depth = P::MaxBlobCommitmentsPerBlock::LEN
            .next_power_of_two()
            .ilog2() as usize;
        let max = P::MaxBlobCommitmentsPerBlock::LEN as u64;
        if sidecar.index.0 >= max {
            return false;
        }
        let field = BeaconBlockBody::<P>::field_index(BLOB_KZG_COMMITMENTS_FIELD);
        let gindex = field
            .concat(GeneralizedIndex::new(2))
            .concat(GeneralizedIndex::at(depth, sidecar.index.0));
        let proof = MerkleProof {
            branch: sidecar
                .kzg_commitment_inclusion_proof
                .iter()
                .map(|node| Root(node.0))
                .collect(),
        };
        proof.verify(
            sidecar.kzg_commitment.hash_tree_root(),
            gindex,
            sidecar.signed_block_header.message.body_root,
        )
    }

    /// Whether the proof opens the commitment to the blob.
    ///
    /// A malformed blob, commitment, or proof never verifies.
    /// See `verify_blob_kzg_proof` in the Deneb polynomial commitments spec.
    #[must_use]
    pub fn has_valid_kzg_proof(self, kzg: &Kzg) -> bool {
        let sidecar = self.0;
        let Ok(blob) = Blob::from_bytes(&sidecar.blob) else {
            return false;
        };
        kzg.verify_blob_kzg_proof(
            &blob,
            &Bytes48::from(sidecar.kzg_commitment.0),
            &Bytes48::from(sidecar.kzg_proof.0),
        )
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn electra_spreads_more_blobs_over_more_subnets() {
        // Mainnet: 6 blobs on 6 subnets in Deneb, 9 blobs on 9 subnets in Electra.
        let config = ChainConfig::mainnet();
        let deneb = BlobSubnets::deneb(&config);
        let electra = BlobSubnets::electra(&config);
        assert_eq!(
            deneb,
            BlobSubnets {
                max_blobs: 6,
                subnet_count: 6,
            }
        );
        assert_eq!(
            electra,
            BlobSubnets {
                max_blobs: 9,
                subnet_count: 9,
            }
        );

        // Blob 7 wraps to subnet 1 in Deneb, and keeps its own subnet in Electra.
        assert_eq!(deneb.subnet(BlobIndex(7)), 1);
        assert_eq!(electra.subnet(BlobIndex(7)), 7);
    }
}
