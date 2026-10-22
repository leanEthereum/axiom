//! Turning a Deneb or Electra block and its blobs into the sidecars that carry them.

use axiom_kzg::{Blob as KzgBlob, Bytes48, Kzg, KzgError};
use axiom_ssz::{Container, GeneralizedIndex, Length, Root, Ssz, Vector};
use axiom_types::{
    BlobIndex, Bytes32, KzgProof, Preset,
    deneb::{self, Blob, BlobKzgCommitments, BlobSidecar, SignedBeaconBlockHeader},
    electra,
};
use thiserror::Error;

/// Index of the commitment list among the fields of a block body.
///
/// Electra appends a field, which keeps the body tree at the same depth.
/// See `get_generalized_index(BeaconBlockBody, "blob_kzg_commitments")` in the Deneb p2p spec.
const BLOB_KZG_COMMITMENTS_FIELD: usize = 11;

/// Blobs a proposer offers that cannot become the sidecars of its block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BlobError {
    /// The blobs do not match the block's commitments in number.
    #[error("block {block_root} commits to {expected} blobs, but {actual} are offered")]
    BlobCountMismatch {
        /// Root of the block.
        block_root: Root,
        /// Commitments in the block.
        expected: usize,
        /// Blobs offered.
        actual: usize,
    },
    /// The proofs are not one per commitment.
    #[error("block {block_root} commits to {expected} blobs, but {actual} proofs are offered")]
    ProofCountMismatch {
        /// Root of the block.
        block_root: Root,
        /// Commitments in the block.
        expected: usize,
        /// Proofs offered.
        actual: usize,
    },
    /// A blob is not 4096 canonical field elements.
    #[error("blob {blob} of block {block_root} is malformed: {source}")]
    MalformedBlob {
        /// Root of the block.
        block_root: Root,
        /// Position of the blob in the commitment list.
        blob: BlobIndex,
        /// Why the bytes are not a blob.
        #[source]
        source: KzgError,
    },
    /// A commitment or a proof is not a point of G1.
    #[error("commitments or proofs of block {block_root} are malformed: {source}")]
    MalformedProofs {
        /// Root of the block.
        block_root: Root,
        /// Why a point is not valid.
        #[source]
        source: KzgError,
    },
    /// The proofs do not open the commitments to the blobs.
    #[error("blob proofs of block {block_root} do not verify")]
    InvalidProofs {
        /// Root of the block.
        block_root: Root,
    },
    /// The block body yields no branch of the preset's depth for a commitment.
    #[error("block {block_root} yields no inclusion proof for blob {blob}")]
    NoInclusionProof {
        /// Root of the block.
        block_root: Root,
        /// Position of the blob in the commitment list.
        blob: BlobIndex,
    },
}

/// A signed Deneb or Electra block about to be published, with its commitments.
///
/// # Overview
///
/// Each blob travels as one sidecar, with the block header.
/// A branch shows the header's body holds the blob's commitment at the blob's index.
/// The branch climbs the commitment list first, then the body:
///
/// ```text
///     branch = list branch to the commitment ++ body branch to the list
/// ```
///
/// See `get_blob_sidecars` in the Deneb validator spec.
#[derive(Clone, Debug)]
pub struct BlockBlobs<'a, P: Preset> {
    /// The header every sidecar carries.
    header: SignedBeaconBlockHeader,
    /// Root of the block, which names it in errors.
    block_root: Root,
    /// The commitments, one per blob.
    commitments: &'a BlobKzgCommitments<P>,
    /// Siblings from the commitment list's leaf up to the body root.
    body_branch: Vec<Root>,
}

impl<'a, P: Preset> BlockBlobs<'a, P> {
    /// The blobs of a Deneb block.
    #[must_use]
    pub fn deneb(block: &'a deneb::SignedBeaconBlock<P>) -> Self {
        let header = SignedBeaconBlockHeader {
            message: block.message.header(),
            signature: block.signature,
        };
        let body = &block.message.body;
        Self::new(header, body, &body.blob_kzg_commitments)
    }

    /// The blobs of an Electra block.
    #[must_use]
    pub fn electra(block: &'a electra::SignedBeaconBlock<P>) -> Self {
        let header = SignedBeaconBlockHeader {
            message: block.message.header(),
            signature: block.signature,
        };
        let body = &block.message.body;
        Self::new(header, body, &body.blob_kzg_commitments)
    }

    /// The blobs of a block whose body holds the commitments at the shared field index.
    fn new<B: Container>(
        header: SignedBeaconBlockHeader,
        body: &B,
        commitments: &'a BlobKzgCommitments<P>,
    ) -> Self {
        Self {
            block_root: header.message.hash_tree_root(),
            body_branch: body.field_proof(BLOB_KZG_COMMITMENTS_FIELD).branch,
            header,
            commitments,
        }
    }

    /// Builds one sidecar per blob, after checking every proof against its commitment.
    ///
    /// # Arguments
    ///
    /// - `blobs`: the blobs, in commitment order.
    /// - `proofs`: one proof per blob, in the same order.
    /// - `kzg`: the verifier.
    ///
    /// # Errors
    ///
    /// Fails when the counts disagree with the commitments, or the proofs do not verify.
    pub fn sidecars(
        &self,
        blobs: &[Blob<P>],
        proofs: &[KzgProof],
        kzg: &Kzg,
    ) -> Result<Vec<BlobSidecar<P>>, BlobError> {
        let block_root = self.block_root;
        let expected = self.commitments.len();
        if blobs.len() != expected {
            return Err(BlobError::BlobCountMismatch {
                block_root,
                expected,
                actual: blobs.len(),
            });
        }
        if proofs.len() != expected {
            return Err(BlobError::ProofCountMismatch {
                block_root,
                expected,
                actual: proofs.len(),
            });
        }
        self.verify(blobs, proofs, kzg)?;

        blobs
            .iter()
            .zip(proofs)
            .zip(self.commitments.iter())
            .enumerate()
            .map(|(position, ((blob, proof), commitment))| {
                let index = BlobIndex(position as u64);
                Ok(BlobSidecar {
                    index,
                    blob: blob.clone(),
                    kzg_commitment: *commitment,
                    kzg_proof: *proof,
                    signed_block_header: self.header.clone(),
                    kzg_commitment_inclusion_proof: self.inclusion_proof(index)?,
                })
            })
            .collect()
    }

    /// Checks every blob proof in one batched pairing check.
    ///
    /// See `verify_blob_kzg_proof_batch` in the Deneb polynomial commitments spec.
    fn verify(&self, blobs: &[Blob<P>], proofs: &[KzgProof], kzg: &Kzg) -> Result<(), BlobError> {
        let block_root = self.block_root;
        let blobs = blobs
            .iter()
            .enumerate()
            .map(|(position, blob)| {
                KzgBlob::from_bytes(blob.as_ref()).map_err(|source| BlobError::MalformedBlob {
                    block_root,
                    blob: BlobIndex(position as u64),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commitments: Vec<Bytes48> = self
            .commitments
            .iter()
            .map(|commitment| Bytes48::from(commitment.0))
            .collect();
        let proofs: Vec<Bytes48> = proofs.iter().map(|proof| Bytes48::from(proof.0)).collect();
        match kzg.verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs) {
            Ok(true) => Ok(()),
            Ok(false) => Err(BlobError::InvalidProofs { block_root }),
            Err(source) => Err(BlobError::MalformedProofs { block_root, source }),
        }
    }

    /// The branch from a commitment up to the body root.
    ///
    /// The list's data tree is the left child of its root, the length the right one.
    /// See `compute_merkle_proof` in the Deneb validator spec.
    fn inclusion_proof(
        &self,
        blob: BlobIndex,
    ) -> Result<Vector<Bytes32, P::KzgCommitmentInclusionProofDepth>, BlobError> {
        let unavailable = || BlobError::NoInclusionProof {
            block_root: self.block_root,
            blob,
        };
        let depth = P::MaxBlobCommitmentsPerBlock::LEN
            .next_power_of_two()
            .ilog2() as usize;
        let index = GeneralizedIndex::new(2).concat(GeneralizedIndex::at(depth, blob.0));
        let (_, proof) = self.commitments.prove(index).ok_or_else(unavailable)?;
        proof
            .branch
            .into_iter()
            .chain(self.body_branch.iter().copied())
            .map(|node| Bytes32(node.0))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| unavailable())
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls12_381::PointDecodeError;
    use axiom_types::{KzgCommitment, Minimal, Slot};

    use super::*;
    use crate::CheckedBlob;

    /// A blob whose first two field elements are a seed and its successor.
    fn blob(seed: u8) -> Blob<Minimal> {
        let mut bytes = Blob::<Minimal>::default().as_ref().to_vec();
        bytes[31] = seed;
        bytes[63] = seed + 1;
        Blob::<Minimal>::try_from(bytes.as_slice()).unwrap()
    }

    /// The commitment and proof of a blob.
    fn open(kzg: &Kzg, blob: &Blob<Minimal>) -> (KzgCommitment, KzgProof) {
        let kzg_blob = KzgBlob::from_bytes(blob.as_ref()).unwrap();
        let commitment = kzg.blob_to_kzg_commitment(&kzg_blob);
        let proof = kzg.compute_blob_kzg_proof(&kzg_blob, &commitment).unwrap();
        (KzgCommitment(commitment.0), KzgProof(proof.0))
    }

    /// An Electra block at slot 7 committing to three blobs, with the blobs and their proofs.
    fn fixture(
        kzg: &Kzg,
    ) -> (
        electra::SignedBeaconBlock<Minimal>,
        Vec<Blob<Minimal>>,
        Vec<KzgProof>,
    ) {
        let mut block = electra::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(7);
        let blobs: Vec<_> = [1, 3, 5].into_iter().map(blob).collect();
        let mut proofs = Vec::new();
        for blob in &blobs {
            let (commitment, proof) = open(kzg, blob);
            block
                .message
                .body
                .blob_kzg_commitments
                .push(commitment)
                .unwrap();
            proofs.push(proof);
        }
        (block, blobs, proofs)
    }

    #[test]
    fn every_built_sidecar_passes_the_receiver_checks() {
        let kzg = Kzg::mainnet();
        let (block, blobs, proofs) = fixture(kzg);

        let sidecars = BlockBlobs::electra(&block)
            .sidecars(&blobs, &proofs, kzg)
            .unwrap();

        // Three sidecars, indexed 0 to 2, each checked as a peer receiving it would.
        let header = SignedBeaconBlockHeader {
            message: block.message.header(),
            signature: block.signature,
        };
        assert_eq!(sidecars.len(), 3);
        for (position, sidecar) in sidecars.iter().enumerate() {
            assert_eq!(sidecar.index, BlobIndex(position as u64));
            assert_eq!(sidecar.blob, blobs[position]);
            assert_eq!(
                sidecar.kzg_commitment,
                block.message.body.blob_kzg_commitments[position]
            );
            assert_eq!(sidecar.kzg_proof, proofs[position]);
            assert_eq!(sidecar.signed_block_header, header);
            assert!(CheckedBlob(sidecar).has_valid_inclusion_proof());
            assert!(CheckedBlob(sidecar).has_valid_kzg_proof(kzg));
        }

        // Mutation: blob 1 claims index 2, whose branch climbs from another leaf.
        let mut moved = sidecars[1].clone();
        moved.index = BlobIndex(2);
        assert!(!CheckedBlob(&moved).has_valid_inclusion_proof());
    }

    #[test]
    fn a_deneb_block_proves_its_commitments_through_its_own_body() {
        let kzg = Kzg::mainnet();
        let (electra_block, blobs, proofs) = fixture(kzg);

        // Fixture state: a Deneb block at slot 7 with the same three commitments.
        let mut block = deneb::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(7);
        block.message.body.blob_kzg_commitments = electra_block.message.body.blob_kzg_commitments;

        let sidecars = BlockBlobs::deneb(&block)
            .sidecars(&blobs, &proofs, kzg)
            .unwrap();

        // The Deneb body differs from the Electra one, so the branch tops differ too.
        // Each still verifies against its own header.
        assert_eq!(sidecars.len(), 3);
        for sidecar in &sidecars {
            assert_eq!(
                sidecar.signed_block_header.message.body_root,
                block.message.body.hash_tree_root()
            );
            assert!(CheckedBlob(sidecar).has_valid_inclusion_proof());
        }
    }

    #[test]
    fn wrong_counts_and_bad_proofs_are_refused() {
        let kzg = Kzg::mainnet();
        let (block, mut blobs, mut proofs) = fixture(kzg);
        let block_root = block.message.hash_tree_root();
        let builder = BlockBlobs::electra(&block);

        // Mutation: offer two blobs for three commitments.
        let last = blobs.pop().unwrap();
        assert_eq!(
            builder.sidecars(&blobs, &proofs, kzg),
            Err(BlobError::BlobCountMismatch {
                block_root,
                expected: 3,
                actual: 2,
            })
        );
        blobs.push(last);

        // Mutation: offer four proofs for three commitments.
        proofs.push(proofs[0]);
        assert_eq!(
            builder.sidecars(&blobs, &proofs, kzg),
            Err(BlobError::ProofCountMismatch {
                block_root,
                expected: 3,
                actual: 4,
            })
        );
        proofs.pop();

        // Mutation: swap the proofs of blobs 0 and 1, so each opens the other's commitment.
        proofs.swap(0, 1);
        assert_eq!(
            builder.sidecars(&blobs, &proofs, kzg),
            Err(BlobError::InvalidProofs { block_root })
        );
        proofs.swap(0, 1);

        // Mutation: proof 2 is 48 zero bytes, which encode no point of G1.
        let valid = proofs[2];
        proofs[2] = KzgProof([0; 48]);
        // A compressed point sets the top bit of its first byte; zero bytes leave it clear.
        assert_eq!(
            builder.sidecars(&blobs, &proofs, kzg),
            Err(BlobError::MalformedProofs {
                block_root,
                source: KzgError::InvalidProof {
                    index: 2,
                    source: PointDecodeError::InvalidCompressionFlag { length: 48 },
                },
            })
        );
        proofs[2] = valid;

        // Mutation: blob 1 starts with 32 bytes of 0xff, above the field modulus.
        let mut bytes = blobs[1].as_ref().to_vec();
        bytes[..32].fill(0xff);
        blobs[1] = Blob::<Minimal>::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            builder.sidecars(&blobs, &proofs, kzg),
            Err(BlobError::MalformedBlob {
                block_root,
                blob: BlobIndex(1),
                source: KzgError::NonCanonicalBlobElement { index: 0 },
            })
        );
    }
}
