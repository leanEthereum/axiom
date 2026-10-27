//! The payload of any fork, ready for the engine to judge.
//!
//! # Overview
//!
//! Each fork hands the engine its own request container, and each container fixes the parameters.
//!
//! ```text
//!     fork       request from               parameters
//!     Bellatrix  the block                  payload V1
//!     Capella    the block                  payload V2
//!     Deneb      the block                  payload V3, versioned hashes, parent root
//!     Electra    the block                  payload V3, versioned hashes, parent root, requests
//!     Fulu       the block                  as Electra
//!     Gloas      the envelope and its bid   payload V4, versioned hashes, parent root, requests
//!     Hstar      the envelope and its bid   as Gloas, with key authorization requests
//! ```
//!
//! The fork then picks the method version from the engine methods table.
//! See `verify_and_notify_new_payload` in the Bellatrix through Electra beacon chain specs.
//! For Gloas, see `verify_execution_payload_envelope` in the fork choice spec.

use axiom_json::Json;
use axiom_ssz::Length;
use axiom_types::{
    ForkName, KzgCommitment, Preset, bellatrix, capella, combined, deneb, electra, gloas, hstar,
};

use crate::{JsonCodec, NewPayloadError};

/// A request for the engine's verdict on one payload, tagged with its fork.
///
/// Fulu kept Electra's request, so those two variants hold the same type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewPayload<P: Preset> {
    /// A Bellatrix payload.
    Bellatrix(bellatrix::NewPayloadRequest<P>),
    /// A Capella payload.
    Capella(capella::NewPayloadRequest<P>),
    /// A Deneb payload.
    Deneb(deneb::NewPayloadRequest<P>),
    /// An Electra payload.
    Electra(electra::NewPayloadRequest<P>),
    /// A Fulu payload, the same type as an Electra one.
    Fulu(electra::NewPayloadRequest<P>),
    /// A Gloas payload, revealed in an envelope after its block.
    Gloas(gloas::NewPayloadRequest<P>),
    /// An Hstar payload, whose requests include key authorizations.
    Hstar(hstar::NewPayloadRequest<P>),
}

impl<P: Preset> NewPayload<P> {
    /// The request for the payload a block carries, or nothing when there is none to judge.
    ///
    /// Before Gloas the payload sits in the block, so everything comes from the block alone.
    /// There is nothing to judge in three cases:
    ///
    /// 1. A phase0 or Altair block predates the merge.
    /// 2. A Bellatrix block carrying the empty payload predates the merge.
    /// 3. A Gloas block carries only a builder's bid; its payload follows in an envelope.
    ///
    /// Why case 2 is safe: once the merge is complete, the transition refuses an empty payload.
    /// Its zero parent hash cannot match the state's latest execution block hash.
    /// See `is_execution_enabled` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn from_block(block: &combined::BeaconBlock<P>) -> Option<Self> {
        match block {
            combined::BeaconBlock::Phase0(_)
            | combined::BeaconBlock::Altair(_)
            | combined::BeaconBlock::Gloas(_)
            | combined::BeaconBlock::Hstar(_) => None,
            combined::BeaconBlock::Bellatrix(block) => {
                let empty = block.body.execution_payload == bellatrix::ExecutionPayload::default();
                (!empty).then(|| Self::Bellatrix(block.new_payload_request()))
            }
            combined::BeaconBlock::Capella(block) => {
                Some(Self::Capella(block.new_payload_request()))
            }
            combined::BeaconBlock::Deneb(block) => Some(Self::Deneb(block.new_payload_request())),
            combined::BeaconBlock::Electra(block) => {
                Some(Self::Electra(block.new_payload_request()))
            }
            combined::BeaconBlock::Fulu(block) => Some(Self::Fulu(block.new_payload_request())),
        }
    }

    /// The request for a revealed payload, from its envelope and the bid its block committed to.
    ///
    /// The bid supplies the blob commitments, and the envelope everything else.
    /// The envelope's parent root is the one the transition checks against the state.
    ///
    /// # Errors
    ///
    /// Fails when the bid commits to more blobs than a block can hold.
    pub fn from_envelope(
        envelope: &combined::SignedExecutionPayloadEnvelope<P>,
        bid: &gloas::ExecutionPayloadBid,
    ) -> Result<Self, NewPayloadError> {
        let commitments = &bid.blob_kzg_commitments;
        let versioned_hashes: gloas::VersionedHashes<P> = commitments
            .iter()
            .map(KzgCommitment::versioned_hash)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| NewPayloadError::TooManyBlobs {
                count: commitments.len(),
                limit: P::MaxBlobCommitmentsPerBlock::LEN,
            })?;
        Ok(match envelope {
            combined::SignedExecutionPayloadEnvelope::Gloas(signed) => {
                Self::Gloas(gloas::NewPayloadRequest {
                    execution_payload: signed.message.payload.clone(),
                    versioned_hashes,
                    parent_beacon_block_root: signed.message.parent_beacon_block_root,
                    execution_requests: signed.message.execution_requests.clone(),
                })
            }
            combined::SignedExecutionPayloadEnvelope::Hstar(signed) => {
                Self::Hstar(hstar::NewPayloadRequest {
                    execution_payload: signed.message.payload.clone(),
                    versioned_hashes,
                    parent_beacon_block_root: signed.message.parent_beacon_block_root,
                    execution_requests: signed.message.execution_requests.clone(),
                })
            }
        })
    }

    /// The fork the payload belongs to.
    #[must_use]
    pub const fn fork(&self) -> ForkName {
        match self {
            Self::Bellatrix(_) => ForkName::Bellatrix,
            Self::Capella(_) => ForkName::Capella,
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
            Self::Gloas(_) => ForkName::Gloas,
            Self::Hstar(_) => ForkName::Hstar,
        }
    }

    /// The method's parameters, in the order the fork's version lists them.
    ///
    /// The requests list follows `get_execution_requests_list` in the Electra and Gloas specs.
    pub(crate) fn params(&self) -> Vec<Json> {
        match self {
            Self::Bellatrix(request) => vec![request.execution_payload.to_json()],
            Self::Capella(request) => vec![request.execution_payload.to_json()],
            Self::Deneb(request) => vec![
                request.execution_payload.to_json(),
                request.versioned_hashes.to_json(),
                request.parent_beacon_block_root.to_json(),
            ],
            Self::Electra(request) | Self::Fulu(request) => vec![
                request.execution_payload.to_json(),
                request.versioned_hashes.to_json(),
                request.parent_beacon_block_root.to_json(),
                request.execution_requests.to_json(),
            ],
            Self::Gloas(request) => vec![
                request.execution_payload.to_json(),
                request.versioned_hashes.to_json(),
                request.parent_beacon_block_root.to_json(),
                request.execution_requests.to_json(),
            ],
            Self::Hstar(request) => vec![
                request.execution_payload.to_json(),
                request.versioned_hashes.to_json(),
                request.parent_beacon_block_root.to_json(),
                request.execution_requests.to_json(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::{List, ProgressiveList};
    use axiom_types::{Hash32, KzgCommitment, Minimal, Root, altair, phase0};

    use super::*;

    #[test]
    fn blocks_without_a_payload_to_judge() {
        // Phase0, Altair, a pre-merge Bellatrix block, and a Gloas block carrying only a bid.
        let blocks = [
            combined::BeaconBlock::<Minimal>::Phase0(phase0::BeaconBlock::default()),
            combined::BeaconBlock::Altair(altair::BeaconBlock::default()),
            combined::BeaconBlock::Bellatrix(bellatrix::BeaconBlock::default()),
            combined::BeaconBlock::Gloas(gloas::BeaconBlock::default()),
        ];
        for block in blocks {
            assert_eq!(
                NewPayload::from_block(&block),
                None,
                "{}",
                block.fork_name()
            );
        }
    }

    #[test]
    fn a_post_merge_bellatrix_block_is_judged() {
        // One non-zero member, the block hash 0x01.., makes the payload non-empty.
        let mut block = bellatrix::BeaconBlock::<Minimal>::default();
        block.body.execution_payload.block_hash = Hash32([0x01; 32]);
        let request = NewPayload::from_block(&combined::BeaconBlock::Bellatrix(block.clone()));
        assert_eq!(
            request,
            Some(NewPayload::Bellatrix(bellatrix::NewPayloadRequest {
                execution_payload: block.body.execution_payload,
            }))
        );
    }

    #[test]
    fn a_fulu_block_keeps_its_fork() {
        // A Fulu block holds Electra's shape, yet its request is tagged Fulu.
        let block = combined::BeaconBlock::<Minimal>::Fulu(electra::BeaconBlock::default());
        let request = NewPayload::from_block(&block).unwrap();
        assert_eq!(request.fork(), ForkName::Fulu);
    }

    #[test]
    fn a_gloas_request_takes_its_hashes_from_the_bid() {
        // Fixture state: a bid with two commitments, an envelope naming parent 0x09...
        let bid = gloas::ExecutionPayloadBid {
            blob_kzg_commitments: ProgressiveList::from(vec![
                KzgCommitment([0x11; 48]),
                KzgCommitment([0x22; 48]),
            ]),
            ..gloas::ExecutionPayloadBid::default()
        };
        let mut signed = gloas::SignedExecutionPayloadEnvelope::<Minimal>::default();
        signed.message.parent_beacon_block_root = Root([0x09; 32]);
        let envelope = signed.message.clone();

        let request = NewPayload::from_envelope(&signed.into(), &bid).unwrap();

        // One versioned hash per commitment, in bid order.
        let hashes = [KzgCommitment([0x11; 48]), KzgCommitment([0x22; 48])]
            .map(|commitment| commitment.versioned_hash());
        assert_eq!(
            request,
            NewPayload::Gloas(gloas::NewPayloadRequest {
                execution_payload: envelope.payload,
                versioned_hashes: List::try_from(hashes.to_vec()).unwrap(),
                parent_beacon_block_root: Root([0x09; 32]),
                execution_requests: gloas::ExecutionRequests::default(),
            })
        );
    }

    #[test]
    fn an_hstar_request_carries_its_key_authorizations() {
        // Fixture state: an Hstar envelope whose payload carried one key authorization.
        let mut signed = hstar::SignedExecutionPayloadEnvelope::<Minimal>::default();
        signed
            .message
            .execution_requests
            .pq_key_authorizations
            .push(hstar::PqKeyAuthorizationRequest::default());
        let requests = signed.message.execution_requests.clone();

        let request =
            NewPayload::from_envelope(&signed.into(), &gloas::ExecutionPayloadBid::default())
                .unwrap();

        // The request is Hstar's, and the authorization reaches the engine with the payload.
        assert_eq!(request.fork(), ForkName::Hstar);
        let NewPayload::Hstar(request) = request else {
            panic!("an Hstar envelope makes an Hstar request");
        };
        assert_eq!(request.execution_requests, requests);
    }

    #[test]
    fn a_bid_with_too_many_blobs_is_refused() {
        // The minimal preset holds at most 4096 commitments a block; the bid claims 4097.
        let bid = gloas::ExecutionPayloadBid {
            blob_kzg_commitments: ProgressiveList::from(vec![KzgCommitment([0; 48]); 4097]),
            ..gloas::ExecutionPayloadBid::default()
        };
        let envelope = gloas::SignedExecutionPayloadEnvelope::<Minimal>::default().into();
        assert_eq!(
            NewPayload::from_envelope(&envelope, &bid),
            Err(NewPayloadError::TooManyBlobs {
                count: 4097,
                limit: 4096
            })
        );
    }
}
