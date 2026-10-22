//! The payload a relay reveals for a signed blinded block, and its check against that block.

use axiom_beacon_json::{ApiJson, ApiJsonError, ApiJsonErrorKind, ForkedJson};
use axiom_json::Json;
use axiom_types::{
    ForkName, KzgCommitment, Preset, bellatrix, capella,
    combined::{BlindedBlockError, ExecutionPayload, SignedBeaconBlock, SignedBlindedBeaconBlock},
    deneb, fulu,
};
use thiserror::Error;

/// The payload a relay reveals once the proposer signed the blinded block.
///
/// From Deneb on, the payload comes with the blobs its transactions carry.
/// Electra kept Deneb's bundle; Fulu's carries cell proofs.
/// See the submit blinded block endpoint of the builder API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevealedPayload<P: Preset> {
    /// A Bellatrix payload.
    Bellatrix(bellatrix::ExecutionPayload<P>),
    /// A Capella payload.
    Capella(capella::ExecutionPayload<P>),
    /// A Deneb payload and its blobs.
    Deneb(deneb::ExecutionPayloadAndBlobsBundle<P>),
    /// An Electra payload and its blobs, the same type as Deneb's.
    Electra(deneb::ExecutionPayloadAndBlobsBundle<P>),
    /// A Fulu payload and its blobs with cell proofs.
    Fulu(fulu::ExecutionPayloadAndBlobsBundle<P>),
}

/// The blobs a revealed payload carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevealedBlobs<P: Preset> {
    /// Blobs with one proof each, from Deneb to Electra.
    Deneb(deneb::BlobsBundle<P>),
    /// Blobs with the cell proofs of each extended blob, from Fulu on.
    Fulu(fulu::BlobsBundle<P>),
}

/// A signed full block, rebuilt from its blinded form and the revealed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnblindedBlock<P: Preset> {
    /// The signed full block, under the proposer's original signature.
    pub block: SignedBeaconBlock<P>,

    /// Its blobs, from Deneb on.
    pub blobs: Option<RevealedBlobs<P>>,
}

/// A revealed payload that does not complete the signed blinded block.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RevealError {
    /// The payload belongs to another fork than the block.
    #[error("a {payload} payload cannot complete a {block} block")]
    Fork {
        /// The block's fork.
        block: ForkName,
        /// The payload's fork.
        payload: ForkName,
    },

    /// The bundle holds another number of commitments than the block.
    #[error("bundle carries {actual} blob commitments, the block {expected}")]
    CommitmentCount {
        /// Commitments in the block.
        expected: usize,
        /// Commitments in the bundle.
        actual: usize,
    },

    /// A commitment of the bundle differs from the block's at the same index.
    #[error("bundle commitment {index} is {actual}, the block has {expected}")]
    Commitment {
        /// Position of the commitment.
        index: usize,
        /// The block's commitment.
        expected: KzgCommitment,
        /// The bundle's commitment.
        actual: KzgCommitment,
    },

    /// The bundle holds another number of blobs than commitments.
    #[error("bundle carries {actual} blobs for {expected} commitments")]
    BlobCount {
        /// Commitments in the bundle.
        expected: usize,
        /// Blobs in the bundle.
        actual: usize,
    },

    /// The bundle holds another number of proofs than its blobs need.
    #[error("bundle carries {actual} proofs, its blobs need {expected}")]
    ProofCount {
        /// Proofs the blobs need.
        expected: usize,
        /// Proofs in the bundle.
        actual: usize,
    },

    /// The payload is not the one the block's header commits to.
    #[error("revealed payload does not unblind the block: {0}")]
    Unblind(#[from] BlindedBlockError),
}

impl<P: Preset> RevealedPayload<P> {
    /// The fork the payload belongs to.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Bellatrix(_) => ForkName::Bellatrix,
            Self::Capella(_) => ForkName::Capella,
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
        }
    }

    /// Completes a signed blinded block with this payload.
    ///
    /// # Invariants
    ///
    /// A blinded block and its full block share one root, so the signature carries over.
    /// The payload root equals the header root exactly when the payload is the committed one.
    /// The blobs must open the commitments the block signed, in the same order.
    ///
    /// The blobs' KZG proofs are not checked here; publication verifies them like any sidecar.
    ///
    /// # Errors
    ///
    /// Fails when the payload is of another fork, or differs from the committed header.
    /// Fails when the bundle's commitments differ from the block's, or its counts disagree.
    pub fn unblind(
        self,
        block: SignedBlindedBeaconBlock<P>,
    ) -> Result<UnblindedBlock<P>, RevealError> {
        if self.fork_name() != block.fork_name() {
            return Err(RevealError::Fork {
                block: block.fork_name(),
                payload: self.fork_name(),
            });
        }
        let (payload, blobs) = self.into_parts();
        let committed = blobs.as_ref().map_or(&[][..], RevealedBlobs::commitments);
        RevealError::check_commitments(block.blob_kzg_commitments(), committed)?;
        if let Some(blobs) = &blobs {
            blobs.check_counts()?;
        }
        Ok(UnblindedBlock {
            block: block.unblind(payload)?,
            blobs,
        })
    }

    /// The payload and its blobs, apart.
    fn into_parts(self) -> (ExecutionPayload<P>, Option<RevealedBlobs<P>>) {
        match self {
            Self::Bellatrix(payload) => (ExecutionPayload::Bellatrix(payload), None),
            Self::Capella(payload) => (ExecutionPayload::Capella(payload), None),
            Self::Deneb(revealed) => (
                ExecutionPayload::Deneb(revealed.execution_payload),
                Some(RevealedBlobs::Deneb(revealed.blobs_bundle)),
            ),
            Self::Electra(revealed) => (
                ExecutionPayload::Electra(revealed.execution_payload),
                Some(RevealedBlobs::Deneb(revealed.blobs_bundle)),
            ),
            Self::Fulu(revealed) => (
                ExecutionPayload::Fulu(revealed.execution_payload),
                Some(RevealedBlobs::Fulu(revealed.blobs_bundle)),
            ),
        }
    }
}

impl<P: Preset> ForkedJson for RevealedPayload<P> {
    fn to_json(&self) -> Json {
        match self {
            Self::Bellatrix(payload) => payload.to_json(),
            Self::Capella(payload) => payload.to_json(),
            Self::Deneb(revealed) | Self::Electra(revealed) => revealed.to_json(),
            Self::Fulu(revealed) => revealed.to_json(),
        }
    }

    fn from_json_in(fork: ForkName, value: &Json) -> Result<Self, ApiJsonError> {
        Ok(match fork {
            // The builder API reveals payloads from the merge until Gloas enshrines the bid.
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas => {
                return Err(ApiJsonError::new(ApiJsonErrorKind::AbsentInFork {
                    fork,
                    container: "revealed payload",
                }));
            }
            ForkName::Bellatrix => Self::Bellatrix(ApiJson::from_json(value)?),
            ForkName::Capella => Self::Capella(ApiJson::from_json(value)?),
            ForkName::Deneb => Self::Deneb(ApiJson::from_json(value)?),
            ForkName::Electra => Self::Electra(ApiJson::from_json(value)?),
            ForkName::Fulu => Self::Fulu(ApiJson::from_json(value)?),
        })
    }
}

impl<P: Preset> RevealedBlobs<P> {
    /// Commitments to the blobs, in blob order.
    #[must_use]
    pub fn commitments(&self) -> &[KzgCommitment] {
        match self {
            Self::Deneb(bundle) => &bundle.commitments,
            Self::Fulu(bundle) => &bundle.commitments,
        }
    }

    /// Checks that the bundle holds one blob per commitment and the proofs those blobs need.
    ///
    /// Before Fulu each blob has one proof.
    /// From Fulu each blob has one proof per cell of its extension, see EIP-7594.
    fn check_counts(&self) -> Result<(), RevealError> {
        let (commitments, blobs, proofs, proofs_per_blob) = match self {
            Self::Deneb(bundle) => (
                bundle.commitments.len(),
                bundle.blobs.len(),
                bundle.proofs.len(),
                1,
            ),
            Self::Fulu(bundle) => (
                bundle.commitments.len(),
                bundle.blobs.len(),
                bundle.proofs.len(),
                // Invariant: 128 cells per extended blob in every preset, well within usize.
                P::CELLS_PER_EXT_BLOB as usize,
            ),
        };
        if blobs != commitments {
            return Err(RevealError::BlobCount {
                expected: commitments,
                actual: blobs,
            });
        }
        // Bound: at most a few thousand blobs times 128 proofs, far from overflow.
        let expected = blobs * proofs_per_blob;
        if proofs != expected {
            return Err(RevealError::ProofCount {
                expected,
                actual: proofs,
            });
        }
        Ok(())
    }
}

impl RevealError {
    /// Checks that the revealed commitments are the block's, in order.
    fn check_commitments(expected: &[KzgCommitment], actual: &[KzgCommitment]) -> Result<(), Self> {
        if expected.len() != actual.len() {
            return Err(Self::CommitmentCount {
                expected: expected.len(),
                actual: actual.len(),
            });
        }
        match expected.iter().zip(actual).position(|(a, b)| a != b) {
            Some(index) => Err(Self::Commitment {
                index,
                expected: expected[index],
                actual: actual[index],
            }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::{List, Ssz};
    use axiom_types::{BlsSignature, Hash32, KzgProof, Minimal, Slot, bellatrix::UnblindError};

    use super::*;

    /// The Deneb block of every test: slot 9, payload 0x01...01, one blob committed as 0x02...02.
    fn deneb_block() -> deneb::BeaconBlock<Minimal> {
        let mut block = deneb::BeaconBlock::<Minimal> {
            slot: Slot(9),
            ..deneb::BeaconBlock::default()
        };
        block.body.execution_payload.block_hash = Hash32([1; 32]);
        block
            .body
            .blob_kzg_commitments
            .push(KzgCommitment([2; 48]))
            .unwrap();
        block
    }

    /// The block blinded and signed with bytes 0x07...07.
    fn signed_blinded(block: deneb::BeaconBlock<Minimal>) -> SignedBlindedBeaconBlock<Minimal> {
        SignedBlindedBeaconBlock::Deneb(deneb::SignedBlindedBeaconBlock {
            message: block.into(),
            signature: BlsSignature([7; 96]),
        })
    }

    /// The honest reveal: the block's payload, one blob, its commitment and one proof.
    fn reveal() -> deneb::ExecutionPayloadAndBlobsBundle<Minimal> {
        let mut revealed = deneb::ExecutionPayloadAndBlobsBundle::<Minimal> {
            execution_payload: deneb_block().body.execution_payload,
            ..deneb::ExecutionPayloadAndBlobsBundle::default()
        };
        let bundle = &mut revealed.blobs_bundle;
        bundle.commitments.push(KzgCommitment([2; 48])).unwrap();
        bundle.proofs.push(KzgProof([3; 48])).unwrap();
        bundle
            .blobs
            .push(deneb::Blob::<Minimal>::default())
            .unwrap();
        revealed
    }

    /// Unblinds the fixture block with a reveal edited by a test.
    fn unblind_with(
        edit: impl FnOnce(&mut deneb::ExecutionPayloadAndBlobsBundle<Minimal>),
    ) -> Result<UnblindedBlock<Minimal>, RevealError> {
        let mut revealed = reveal();
        edit(&mut revealed);
        RevealedPayload::Deneb(revealed).unblind(signed_blinded(deneb_block()))
    }

    #[test]
    fn the_committed_payload_unblinds_the_block() {
        // The full block keeps the proposer's signature, and the blobs come along.
        assert_eq!(
            unblind_with(|_| {}),
            Ok(UnblindedBlock {
                block: SignedBeaconBlock::Deneb(deneb::SignedBeaconBlock {
                    message: deneb_block(),
                    signature: BlsSignature([7; 96]),
                }),
                blobs: Some(RevealedBlobs::Deneb(reveal().blobs_bundle)),
            })
        );
    }

    #[test]
    fn a_payload_of_another_fork_is_refused() {
        // Fixture state: a Capella payload offered for the Deneb block.
        let revealed = RevealedPayload::<Minimal>::Capella(capella::ExecutionPayload::default());
        assert_eq!(
            revealed.unblind(signed_blinded(deneb_block())),
            Err(RevealError::Fork {
                block: ForkName::Deneb,
                payload: ForkName::Capella,
            })
        );
    }

    #[test]
    fn another_payload_than_the_committed_one_is_refused() {
        // Mutation: the payload's block hash becomes 0x09...09, so its root moves.
        // A payload and its header share one root, so either side's root is the header's.
        let mut payload = deneb_block().body.execution_payload;
        let committed = deneb::ExecutionPayloadHeader::from(&payload).hash_tree_root();
        payload.block_hash = Hash32([9; 32]);
        let actual = payload.hash_tree_root();
        assert_eq!(
            unblind_with(|revealed| revealed.execution_payload = payload),
            Err(RevealError::Unblind(BlindedBlockError::Unblind(
                UnblindError::PayloadMismatch { committed, actual }
            )))
        );
    }

    #[test]
    fn other_commitments_than_the_blocks_are_refused() {
        // A second commitment: two in the bundle against one in the block.
        let result = unblind_with(|revealed| {
            revealed
                .blobs_bundle
                .commitments
                .push(KzgCommitment([4; 48]))
                .unwrap();
        });
        assert_eq!(
            result,
            Err(RevealError::CommitmentCount {
                expected: 1,
                actual: 2,
            })
        );

        // The same count, but commitment 0 is 0x05...05 instead of 0x02...02.
        let result = unblind_with(|revealed| {
            revealed.blobs_bundle.commitments[0] = KzgCommitment([5; 48]);
        });
        assert_eq!(
            result,
            Err(RevealError::Commitment {
                index: 0,
                expected: KzgCommitment([2; 48]),
                actual: KzgCommitment([5; 48]),
            })
        );
    }

    #[test]
    fn a_bundle_with_missing_blobs_or_proofs_is_refused() {
        // No blob for the one commitment.
        let result = unblind_with(|revealed| {
            revealed.blobs_bundle.blobs = List::default();
        });
        assert_eq!(
            result,
            Err(RevealError::BlobCount {
                expected: 1,
                actual: 0,
            })
        );

        // No proof for the one blob.
        let result = unblind_with(|revealed| {
            revealed.blobs_bundle.proofs = List::default();
        });
        assert_eq!(
            result,
            Err(RevealError::ProofCount {
                expected: 1,
                actual: 0,
            })
        );
    }

    #[test]
    fn a_fulu_bundle_needs_every_cell_proof() {
        // Fixture state: a Fulu block committing to one blob, revealed with a single proof.
        // Fulu needs 128 cell proofs per blob, so one is 127 short.
        let mut block = fulu::BeaconBlock::<Minimal>::default();
        block
            .body
            .blob_kzg_commitments
            .push(KzgCommitment([2; 48]))
            .unwrap();
        let signed = SignedBlindedBeaconBlock::Fulu(fulu::SignedBlindedBeaconBlock {
            message: block.clone().into(),
            signature: BlsSignature([7; 96]),
        });
        let mut revealed = fulu::ExecutionPayloadAndBlobsBundle::<Minimal> {
            execution_payload: block.body.execution_payload,
            ..fulu::ExecutionPayloadAndBlobsBundle::default()
        };
        let bundle = &mut revealed.blobs_bundle;
        bundle.commitments.push(KzgCommitment([2; 48])).unwrap();
        bundle.proofs.push(KzgProof([3; 48])).unwrap();
        bundle.blobs.push(fulu::Blob::<Minimal>::default()).unwrap();

        assert_eq!(
            RevealedPayload::Fulu(revealed).unblind(signed),
            Err(RevealError::ProofCount {
                expected: 128,
                actual: 1,
            })
        );
    }

    #[test]
    fn json_reads_the_named_fork() {
        // A Capella payload's JSON reads back as Capella, and Gloas has no revealed payload.
        let revealed = RevealedPayload::<Minimal>::Capella(capella::ExecutionPayload::default());
        let json = revealed.to_json();
        assert_eq!(
            RevealedPayload::from_json_in(ForkName::Capella, &json),
            Ok(revealed)
        );
        assert_eq!(
            RevealedPayload::<Minimal>::from_json_in(ForkName::Gloas, &json),
            Err(ApiJsonError::new(ApiJsonErrorKind::AbsentInFork {
                fork: ForkName::Gloas,
                container: "revealed payload",
            }))
        );
    }
}
