//! Answers to peers' requests, from the chain's data.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use axiom_p2p::{
    PeerId,
    eth::reqresp::{MetaData, Protocol, ResponseChunk, ResponseCode, Status},
    swarm::{InboundRequestId, NetworkHandle},
};
use axiom_ssz::{BitVector, Ssz};
use axiom_types::{Preset, Root};
use tracing::debug;

use super::{
    requests::{
        BlobsByRootRequest, BlocksByHeadRequest, BlocksByRangeRequest, BlocksByRootRequest,
        ColumnsByRangeRequest, ColumnsByRootRequest, EnvelopesByRootRequest, SlotRangeRequest,
        UpdatesByRangeRequest,
    },
    responder::{RequestBody, Responder},
};
use crate::{Chain, ChainError, ChainHandle};

/// What the node tells peers about itself.
#[derive(Debug)]
pub(crate) struct LocalMetadata {
    /// Bumped whenever the metadata changes, so peers know to fetch it again.
    pub(crate) seq_number: AtomicU64,
    /// Long-lived attestation subnets, one bit per subnet.
    pub(crate) attnets: AtomicU64,
    /// Custody group count advertised to peers.
    pub(crate) custody_group_count: u64,
}

/// Bytes of a status in its first version: the second version appends one field.
///
/// Both are fixed-size containers, so the older encoding is a prefix of the newer.
/// See Status v1 in the phase0 p2p spec and Status v2 in the Fulu p2p spec.
const STATUS_V1_BYTES: usize = 84;

/// Bytes of metadata in its second version: the third version appends one field.
///
/// See MetaData v2 in the Altair p2p spec and MetaData v3 in the Fulu p2p spec.
const METADATA_V2_BYTES: usize = 17;

/// Serves inbound requests from the chain's data.
///
/// Each method answers from one chain query, so a request never sees a half-applied block.
/// Peers of every fork are served: older method versions answer from the same data.
#[derive(Debug)]
pub(crate) struct RequestServer<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The network, for responding.
    network: NetworkHandle,
    /// The node's metadata.
    metadata: Arc<LocalMetadata>,
}

impl<P: Preset> RequestServer<P> {
    /// A server over the chain.
    pub(crate) const fn new(
        chain: ChainHandle<P>,
        network: NetworkHandle,
        metadata: Arc<LocalMetadata>,
    ) -> Self {
        Self {
            chain,
            network,
            metadata,
        }
    }

    /// The node's status, as the handshake sends it.
    ///
    /// # Errors
    ///
    /// Fails when the chain has stopped or the database is unreadable.
    pub(crate) async fn status(&self) -> Result<Status, ChainError> {
        self.chain
            .run(|chain| Responder::new(chain).status())
            .await
            .map_err(|_| ChainError::Stopped)?
    }

    /// Answers one request and closes its stream.
    pub(crate) async fn answer(
        &self,
        peer: &PeerId,
        id: InboundRequestId,
        protocol: Protocol,
        payload: Vec<u8>,
    ) {
        let chunks = match self.chunks(protocol, payload).await {
            Ok(chunks) => chunks,
            Err(chunk) => vec![chunk],
        };
        debug!(%peer, ?protocol, chunks = chunks.len(), "answered request");
        // A peer that hung up needs no answer.
        let _stopped = self.network.respond(id, chunks).await;
    }

    /// The response chunks for a request, or the one error chunk that ends it.
    async fn chunks(
        &self,
        protocol: Protocol,
        payload: Vec<u8>,
    ) -> Result<Vec<ResponseChunk>, ResponseChunk> {
        match protocol {
            Protocol::StatusV2 | Protocol::StatusV1 => {
                let status = self.status().await.map_err(|error| {
                    ResponseChunk::error(ResponseCode::ServerError, &error.to_string())
                })?;
                let mut bytes = status.encode();
                if protocol == Protocol::StatusV1 {
                    bytes.truncate(STATUS_V1_BYTES);
                }
                Ok(vec![ResponseChunk::success(None, bytes)])
            }
            Protocol::PingV1 => {
                let seq = self.metadata.seq_number.load(Ordering::Relaxed);
                Ok(vec![ResponseChunk::success(None, seq.encode())])
            }
            Protocol::MetaDataV3 | Protocol::MetaDataV2 => {
                let mut bytes = self.metadata().encode();
                if protocol == Protocol::MetaDataV2 {
                    bytes.truncate(METADATA_V2_BYTES);
                }
                Ok(vec![ResponseChunk::success(None, bytes)])
            }
            // The goodbye method has no response; the stream just closes.
            Protocol::GoodbyeV1 => Ok(Vec::new()),
            Protocol::BeaconBlocksByRangeV2 => {
                let request = RequestBody(&payload).decode::<BlocksByRangeRequest>()?;
                self.query(move |chain| Responder::new(chain).blocks_by_range(request))
                    .await
            }
            Protocol::BeaconBlocksByRootV2 => {
                let request = RequestBody(&payload).decode::<BlocksByRootRequest>()?;
                self.query(move |chain| Responder::new(chain).blocks_by_root(&request))
                    .await
            }
            Protocol::BeaconBlocksByHeadV1 => {
                let request = RequestBody(&payload).decode::<BlocksByHeadRequest>()?;
                self.query(move |chain| Responder::new(chain).blocks_by_head(request))
                    .await
            }
            Protocol::DataColumnSidecarsByRangeV1 => {
                let request = RequestBody(&payload).decode::<ColumnsByRangeRequest<P>>()?;
                self.query(move |chain| Responder::new(chain).columns_by_range(&request))
                    .await
            }
            Protocol::DataColumnSidecarsByRootV1 => {
                let request = RequestBody(&payload).decode::<ColumnsByRootRequest<P>>()?;
                self.query(move |chain| Responder::new(chain).columns_by_root(&request))
                    .await
            }
            Protocol::BlobSidecarsByRangeV1 => {
                let request = RequestBody(&payload).decode::<SlotRangeRequest>()?;
                self.query(move |chain| Responder::new(chain).blobs_by_range(request))
                    .await
            }
            Protocol::BlobSidecarsByRootV1 => {
                let request = RequestBody(&payload).decode::<BlobsByRootRequest>()?;
                self.query(move |chain| Responder::new(chain).blobs_by_root(&request))
                    .await
            }
            Protocol::ExecutionPayloadEnvelopesByRangeV1 => {
                let request = RequestBody(&payload).decode::<SlotRangeRequest>()?;
                self.query(move |chain| Responder::new(chain).envelopes_by_range(request))
                    .await
            }
            Protocol::ExecutionPayloadEnvelopesByRootV1 => {
                let request = RequestBody(&payload).decode::<EnvelopesByRootRequest>()?;
                self.query(move |chain| Responder::new(chain).envelopes_by_root(&request))
                    .await
            }
            Protocol::LightClientBootstrapV1 => {
                let root = RequestBody(&payload).decode::<Root>()?;
                self.light_client(move |chain| Responder::new(chain).light_client_bootstrap(&root))
                    .await
            }
            Protocol::LightClientUpdatesByRangeV1 => {
                let request = RequestBody(&payload).decode::<UpdatesByRangeRequest>()?;
                self.chain
                    .run(move |chain| Responder::new(chain).light_client_updates(request))
                    .await
                    .map_err(|_| ResponseChunk::error(ResponseCode::ServerError, "chain stopped"))
            }
            Protocol::LightClientFinalityUpdateV1 => {
                self.light_client(|chain| Responder::new(chain).light_client_finality_update())
                    .await
            }
            Protocol::LightClientOptimisticUpdateV1 => {
                self.light_client(|chain| Responder::new(chain).light_client_optimistic_update())
                    .await
            }
        }
    }

    /// Runs a light client query that answers one chunk, or none when the data is missing.
    ///
    /// The spec answers missing data with the resource unavailable code.
    async fn light_client(
        &self,
        query: impl FnOnce(&mut Chain<P>) -> Vec<ResponseChunk> + Send + 'static,
    ) -> Result<Vec<ResponseChunk>, ResponseChunk> {
        let chunks = self
            .chain
            .run(query)
            .await
            .map_err(|_| ResponseChunk::error(ResponseCode::ServerError, "chain stopped"))?;
        if chunks.is_empty() {
            return Err(ResponseChunk::error(
                ResponseCode::ResourceUnavailable,
                "no light client data",
            ));
        }
        Ok(chunks)
    }

    /// Runs a query on the chain thread, mapping its failure to a server error.
    async fn query(
        &self,
        query: impl FnOnce(&mut Chain<P>) -> Result<Vec<ResponseChunk>, ChainError> + Send + 'static,
    ) -> Result<Vec<ResponseChunk>, ResponseChunk> {
        self.chain
            .run(query)
            .await
            .map_err(|_| ResponseChunk::error(ResponseCode::ServerError, "chain stopped"))?
            .map_err(|error| ResponseChunk::error(ResponseCode::ServerError, &error.to_string()))
    }

    /// The metadata, as of now.
    fn metadata(&self) -> MetaData {
        let bits = self.metadata.attnets.load(Ordering::Relaxed);
        let mut attnets = BitVector::default();
        for index in 0..64 {
            attnets.set(index, bits >> index & 1 == 1);
        }
        MetaData {
            seq_number: self.metadata.seq_number.load(Ordering::Relaxed),
            attnets,
            syncnets: BitVector::default(),
            custody_group_count: self.metadata.custody_group_count,
        }
    }
}
