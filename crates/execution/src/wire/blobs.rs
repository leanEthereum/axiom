//! Blobs with their proofs, in the bundle of a built payload and from the engine's pool.
//!
//! Version 1 is defined in `src/engine/cancun.md`, version 2 in `osaka.md`.
//! Version 1 carries one KZG proof per blob.
//! Since PeerDAS, version 2 carries one proof per cell of the extended blob.
//!
//! ```text
//!     BlobsBundleV1   commitments  n x DATA 48
//!                     proofs       n x DATA 48, one per blob
//!                     blobs        n x DATA 131072
//!
//!     BlobsBundleV2   commitments  n x DATA 48
//!                     proofs       n * CELLS_PER_EXT_BLOB x DATA 48, blob by blob
//!                     blobs        n x DATA 131072
//!
//!     BlobAndProofV1  blob DATA 131072, proof DATA 48
//!     BlobAndProofV2  blob DATA 131072, proofs CELLS_PER_EXT_BLOB x DATA 48
//! ```
//!
//! Version 2 proofs run blob by blob, so blob 1 cell 0 follows blob 0 cell 127.

use axiom_json::Json;
use axiom_ssz::{Length, List, Vector};
use axiom_types::{
    KzgProof, Preset,
    deneb::{Blob, BlobKzgCommitments},
};

use super::{Fields, Items, JsonCodec, Reader};
use crate::{GetBlobsVersion, WireError, WireErrorKind};

/// One proof per blob of a block.
pub type BlobProofs<P> = List<KzgProof, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// Cell proofs of every blob in a block, blob by blob.
pub type CellProofs<P> = List<KzgProof, <P as Preset>::MaxCellProofsPerBlock>;

/// Blobs of a block.
pub type Blobs<P> = List<Blob<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// The blobs of a payload built before Osaka, with their commitments and proofs.
///
/// Decoding guarantees one commitment and one proof per blob.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobsBundleV1<P: Preset> {
    /// KZG commitment of each blob.
    pub commitments: BlobKzgCommitments<P>,

    /// KZG proof of each blob.
    pub proofs: BlobProofs<P>,

    /// The blobs.
    pub blobs: Blobs<P>,
}

impl<P: Preset> JsonCodec for BlobsBundleV1<P> {
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

        // Cancun rule 4: the three arrays have one entry per blob.
        let blobs = bundle.blobs.len();
        check_length(blobs, bundle.commitments.len())
            .map_err(|error| error.in_member("commitments"))?;
        check_length(blobs, bundle.proofs.len()).map_err(|error| error.in_member("proofs"))?;
        Ok(bundle)
    }
}

/// The blobs of a payload built from Osaka on, with their commitments and cell proofs.
///
/// Decoding guarantees one commitment per blob and one proof per cell of each extended blob.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobsBundleV2<P: Preset> {
    /// KZG commitment of each blob.
    pub commitments: BlobKzgCommitments<P>,

    /// KZG proof of each cell of each extended blob.
    pub proofs: CellProofs<P>,

    /// The blobs.
    pub blobs: Blobs<P>,
}

impl<P: Preset> JsonCodec for BlobsBundleV2<P> {
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
        check_length(blobs, bundle.commitments.len())
            .map_err(|error| error.in_member("commitments"))?;

        // Osaka rule 3: CELLS_PER_EXT_BLOB proofs per blob; 128 on both presets.
        let cells = blobs * P::CellsPerExtBlob::LEN;
        check_length(cells, bundle.proofs.len()).map_err(|error| error.in_member("proofs"))?;
        Ok(bundle)
    }
}

/// Refuses a list whose length disagrees with the one the other lists imply.
const fn check_length(expected: usize, actual: usize) -> Result<(), WireError> {
    if actual == expected {
        Ok(())
    } else {
        Err(WireError::new(WireErrorKind::LengthMismatch {
            expected,
            actual,
        }))
    }
}

/// One blob from the engine's pool with its single proof, before Osaka.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobAndProofV1<P: Preset> {
    /// The blob.
    pub blob: Blob<P>,

    /// KZG proof of the blob against its commitment.
    pub proof: KzgProof,
}

impl<P: Preset> JsonCodec for BlobAndProofV1<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("blob", self.blob.to_json()),
            ("proof", self.proof.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            blob: fields.required("blob")?,
            proof: fields.required("proof")?,
        })
    }
}

/// One blob from the engine's pool with its cell proofs, from Osaka on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobAndProofV2<P: Preset> {
    /// The blob.
    pub blob: Blob<P>,

    /// KZG proof of each cell of the extended blob.
    pub proofs: Vector<KzgProof, P::CellsPerExtBlob>,
}

impl<P: Preset> JsonCodec for BlobAndProofV2<P> {
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

/// The engine's answer to a request for pool blobs, in request order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetBlobsResponse<P: Preset> {
    /// Each blob, or nothing where the pool lacks it.
    V1(Vec<Option<BlobAndProofV1<P>>>),

    /// Every blob, or nothing when the pool lacks any one of them.
    V2(Option<Vec<BlobAndProofV2<P>>>),
}

impl<P: Preset> GetBlobsResponse<P> {
    /// Reads the reply of a version, given how many blobs were requested.
    ///
    /// # Errors
    ///
    /// Fails when an entry is malformed, or the entry count differs from the request's.
    pub(crate) fn decode(
        version: GetBlobsVersion,
        value: &Json,
        requested: usize,
    ) -> Result<Self, WireError> {
        match version {
            // Cancun: always an array, with null for each missing blob.
            GetBlobsVersion::V1 => {
                let items = Reader::new(value).items()?;
                check_length(requested, items.len())?;
                items.decode().map(Self::V1)
            }
            // Osaka: null is the all-or-nothing answer for any missing blob.
            GetBlobsVersion::V2 => {
                if value.is_null() {
                    return Ok(Self::V2(None));
                }
                let items = value
                    .as_array()
                    .map(Items::new)
                    .ok_or_else(|| WireError::wrong_type("array or null", value))?;
                check_length(requested, items.len())?;
                items.decode().map(|blobs| Self::V2(Some(blobs)))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use axiom_json::Data;
    use axiom_ssz::ByteVector;
    use axiom_types::{KzgCommitment, Minimal};
    use proptest::prelude::*;

    use super::*;

    /// Any minimal-preset blob of one repeated byte; 128 KiB of random bytes slows every case.
    pub(crate) fn blob() -> impl Strategy<Value = Blob<Minimal>> {
        any::<u8>().prop_map(|byte| {
            ByteVector::try_from(vec![byte; 131_072].as_slice()).expect("exactly one blob")
        })
    }

    /// Any version 1 bundle of up to two blobs.
    pub(crate) fn bundle_v1() -> impl Strategy<Value = BlobsBundleV1<Minimal>> {
        proptest::collection::vec((blob(), any::<u8>()), 0..=2).prop_map(|entries| BlobsBundleV1 {
            commitments: entries
                .iter()
                .map(|&(_, byte)| KzgCommitment([byte; 48]))
                .collect::<Vec<_>>()
                .try_into()
                .expect("within the limit"),
            proofs: entries
                .iter()
                .map(|&(_, byte)| KzgProof([byte.wrapping_add(1); 48]))
                .collect::<Vec<_>>()
                .try_into()
                .expect("within the limit"),
            blobs: entries
                .into_iter()
                .map(|(blob, _)| blob)
                .collect::<Vec<_>>()
                .try_into()
                .expect("within the limit"),
        })
    }

    /// Any version 2 bundle of up to two blobs, each with 128 cell proofs.
    pub(crate) fn bundle_v2() -> impl Strategy<Value = BlobsBundleV2<Minimal>> {
        bundle_v1().prop_map(|bundle| BlobsBundleV2 {
            proofs: bundle
                .proofs
                .iter()
                .flat_map(|&proof| [proof; 128])
                .collect::<Vec<_>>()
                .try_into()
                .expect("within the limit"),
            commitments: bundle.commitments,
            blobs: bundle.blobs,
        })
    }

    proptest! {
        #[test]
        fn bundles_round_trip(v1 in bundle_v1(), v2 in bundle_v2()) {
            prop_assert_eq!(BlobsBundleV1::from_json(&v1.to_json()), Ok(v1));
            prop_assert_eq!(BlobsBundleV2::from_json(&v2.to_json()), Ok(v2));
        }

        #[test]
        fn pool_blobs_round_trip(blob in blob(), byte in any::<u8>()) {
            let v1 = BlobAndProofV1::<Minimal> { blob: blob.clone(), proof: KzgProof([byte; 48]) };
            prop_assert_eq!(BlobAndProofV1::from_json(&v1.to_json()), Ok(v1));

            let proofs = Vector::try_from(vec![KzgProof([byte; 48]); 128]).expect("128 cells");
            let v2 = BlobAndProofV2::<Minimal> { blob, proofs };
            prop_assert_eq!(BlobAndProofV2::from_json(&v2.to_json()), Ok(v2));
        }
    }

    #[test]
    fn a_v1_bundle_needs_one_proof_per_blob() {
        // One blob and one commitment, but two proofs.
        let text = format!(
            r#"{{"commitments":["0x{c}"],"proofs":["0x{p}","0x{p}"],"blobs":["{b}"]}}"#,
            c = "11".repeat(48),
            p = "22".repeat(48),
            b = vec![0; 131_072].to_data(),
        );
        let error = BlobsBundleV1::<Minimal>::from_json(&Json::parse(text).unwrap());
        assert_eq!(
            error,
            Err(WireError::new(WireErrorKind::LengthMismatch {
                expected: 1,
                actual: 2
            })
            .in_member("proofs"))
        );
    }
}
