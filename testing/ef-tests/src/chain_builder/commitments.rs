//! Blob commitments a built block carries, chosen by the caller.

use axiom_types::{KzgCommitment, Preset, combined};

use crate::chain_builder::ChainBuilderError;

/// The commitments to place in a block body, one per blob.
///
/// The caller holds the blobs and their proofs.
/// The builder never checks them: without an engine, nothing compares versioned hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlobCommitments<'a>(pub(crate) &'a [KzgCommitment]);

impl BlobCommitments<'_> {
    /// Places the commitments in the body of a block that carries them.
    ///
    /// No commitment leaves any block unchanged.
    /// Deneb, Electra, and Fulu bodies hold commitments; other forks have none to hold.
    ///
    /// # Errors
    ///
    /// Fails when the block's fork carries no commitments in its body.
    /// Fails when the commitments overflow the body's list.
    pub(crate) fn attach<P: Preset>(
        self,
        block: &mut combined::BeaconBlock<P>,
    ) -> Result<(), ChainBuilderError> {
        if self.0.is_empty() {
            return Ok(());
        }
        let (slot, fork) = (block.slot(), block.fork_name());
        let list = match block {
            combined::BeaconBlock::Deneb(block) => &mut block.body.blob_kzg_commitments,
            combined::BeaconBlock::Electra(block) | combined::BeaconBlock::Fulu(block) => {
                &mut block.body.blob_kzg_commitments
            }
            combined::BeaconBlock::Phase0(_)
            | combined::BeaconBlock::Altair(_)
            | combined::BeaconBlock::Bellatrix(_)
            | combined::BeaconBlock::Capella(_)
            | combined::BeaconBlock::Gloas(_) => {
                return Err(ChainBuilderError::NoBlobCommitments { slot, fork });
            }
        };
        *list = self
            .0
            .to_vec()
            .try_into()
            .map_err(|_| ChainBuilderError::TooManyCommitments {
                slot,
                count: self.0.len(),
                limit: P::MAX_BLOB_COMMITMENTS_PER_BLOCK as usize,
            })?;
        Ok(())
    }
}
