//! Blobs with their cell proofs: BlobsBundleV2 and BlobAndProofV2.
//!
//! Both are defined in `src/engine/osaka.md`.
//! Since PeerDAS, a blob carries one KZG proof per cell of its extended form, not one per blob.
//!
//! ```text
//!     BlobsBundleV2   commitments  n x DATA 48
//!                     blobs        n x DATA 131072
//!                     proofs       n * CELLS_PER_EXT_BLOB x DATA 48, blob by blob
//!
//!     proofs: [ b0c0 b0c1 .. b0c127 | b1c0 .. b1c127 | ... ]   (bXcY = blob X, cell Y)
//! ```

use axiom_json::Json;
use axiom_ssz::{Length, List, Vector};
use axiom_types::{
    KzgProof, Preset,
    fulu::{Blob, BlobKzgCommitments},
};

use super::{Fields, JsonCodec};
use crate::{WireError, WireErrorKind};

/// Cell proofs of every blob in a block, blob by blob.
pub type CellProofs<P> = List<KzgProof, <P as Preset>::MaxCellProofsPerBlock>;

/// Blobs of a block.
pub type Blobs<P> = List<Blob<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// The blobs of a built payload, with their commitments and cell proofs.
///
/// Decoding guarantees one commitment per blob and one proof per cell of each extended blob.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobsBundle<P: Preset> {
    /// KZG commitment of each blob.
    pub commitments: BlobKzgCommitments<P>,

    /// KZG proof of each cell of each extended blob.
    pub proofs: CellProofs<P>,

    /// The blobs.
    pub blobs: Blobs<P>,
}

impl<P: Preset> JsonCodec for BlobsBundle<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("commitments", self.commitments.to_json()),
            ("proofs", self.proofs.to_json()),
            ("blobs", self.blobs.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        let bundle = Self {
            commitments: fields.required("commitments")?,
            proofs: fields.required("proofs")?,
            blobs: fields.required("blobs")?,
        };

        // Osaka rule 3: one commitment per blob.
        let blobs = bundle.blobs.len();
        if bundle.commitments.len() != blobs {
            return Err(WireError::new(WireErrorKind::LengthMismatch {
                expected: blobs,
                actual: bundle.commitments.len(),
            })
            .in_member("commitments"));
        }

        // Osaka rule 3: CELLS_PER_EXT_BLOB proofs per blob; 128 on both presets.
        let cells = blobs * P::CellsPerExtBlob::LEN;
        if bundle.proofs.len() != cells {
            return Err(WireError::new(WireErrorKind::LengthMismatch {
                expected: cells,
                actual: bundle.proofs.len(),
            })
            .in_member("proofs"));
        }
        Ok(bundle)
    }
}

/// One blob from the engine's pool with its cell proofs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobAndProof<P: Preset> {
    /// The blob.
    pub blob: Blob<P>,

    /// KZG proof of each cell of the extended blob.
    pub proofs: Vector<KzgProof, P::CellsPerExtBlob>,
}

impl<P: Preset> JsonCodec for BlobAndProof<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("blob", self.blob.to_json()),
            ("proofs", self.proofs.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        // The vector type enforces exactly CELLS_PER_EXT_BLOB proofs.
        let fields = Fields::of(value)?;
        Ok(Self {
            blob: fields.required("blob")?,
            proofs: fields.required("proofs")?,
        })
    }
}
