//! Answers to peers' requests: status, metadata, blocks, and columns.

use std::sync::atomic::{AtomicU64, Ordering};

use axiom_p2p::{
    PeerId,
    eth::reqresp::{MetaData, Protocol, ResponseChunk, ResponseCode, Status},
    swarm::{InboundRequestId, NetworkHandle},
};
use axiom_ssz::{BitVector, Ssz};
use axiom_types::{ColumnIndex, Epoch, Preset, Root, SignedBeaconBlock, Slot};
use tracing::debug;

use super::requests::{
    BlocksByHeadRequest, BlocksByRangeRequest, BlocksByRootRequest, ColumnsByRangeRequest,
    ColumnsByRootRequest,
};
use crate::{Chain, ChainError, ChainHandle};

/// Most blocks served for one request: MAX_REQUEST_BLOCKS_DENEB.
const MAX_BLOCKS: u64 = 128;

/// What the node tells peers about itself.
#[derive(Debug)]
pub(crate) struct LocalMetadata {
    /// Bumped whenever the metadata changes, so peers know to fetch it again.
    pub(crate) seq_number: AtomicU64,
    /// Long-lived attestation subnets, as a bitfield of 64.
    pub(crate) attnets: [bool; 64],
    /// Custody group count advertised to peers.
    pub(crate) custody_group_count: u64,
}

/// Serves inbound requests from the chain's data.
///
/// Each method answers from one chain query, so a request never sees a half-applied block.
#[derive(Debug)]
pub(crate) struct RequestServer<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The network, for responding.
    network: NetworkHandle,
    /// The node's metadata.
    metadata: LocalMetadata,
}

impl<P: Preset> RequestServer<P> {
    /// A server over the chain.
    pub(crate) const fn new(
        chain: ChainHandle<P>,
        network: NetworkHandle,
        metadata: LocalMetadata,
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
            .run(Self::status_of)
            .await
            .map_err(|_| ChainError::Missing("running chain"))?
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
            Protocol::StatusV2 => {
                let status = self
                    .status()
                    .await
                    .map_err(|error| Self::server_error(&error))?;
                Ok(vec![ResponseChunk::success(None, status.encode())])
            }
            Protocol::PingV1 => {
                let seq = self.metadata.seq_number.load(Ordering::Relaxed);
                Ok(vec![ResponseChunk::success(None, seq.encode())])
            }
            Protocol::MetaDataV3 => {
                Ok(vec![ResponseChunk::success(None, self.metadata().encode())])
            }
            // The goodbye method has no response; the stream just closes.
            Protocol::GoodbyeV1 => Ok(Vec::new()),
            Protocol::BeaconBlocksByRangeV2 => {
                let request = Self::decode::<BlocksByRangeRequest>(&payload)?;
                self.query(move |chain| Self::blocks_by_range(chain, request))
                    .await
            }
            Protocol::BeaconBlocksByRootV2 => {
                let request = Self::decode::<BlocksByRootRequest>(&payload)?;
                self.query(move |chain| Self::blocks_by_root(chain, &request))
                    .await
            }
            Protocol::BeaconBlocksByHeadV1 => {
                let request = Self::decode::<BlocksByHeadRequest>(&payload)?;
                self.query(move |chain| Self::blocks_by_head(chain, request))
                    .await
            }
            Protocol::DataColumnSidecarsByRangeV1 => {
                let request = Self::decode::<ColumnsByRangeRequest<P>>(&payload)?;
                self.query(move |chain| Self::columns_by_range(chain, &request))
                    .await
            }
            Protocol::DataColumnSidecarsByRootV1 => {
                let request = Self::decode::<ColumnsByRootRequest<P>>(&payload)?;
                self.query(move |chain| Self::columns_by_root(chain, &request))
                    .await
            }
            // Superseded methods: Fulu peers use the versions above.
            Protocol::StatusV1
            | Protocol::MetaDataV2
            | Protocol::BlobSidecarsByRangeV1
            | Protocol::BlobSidecarsByRootV1 => Err(ResponseChunk::error(
                ResponseCode::ResourceUnavailable,
                "method not served after Fulu",
            )),
        }
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
            .map_err(|error| Self::server_error(&error))
    }

    /// The node's status, read on the chain thread.
    fn status_of(chain: &mut Chain<P>) -> Result<Status, ChainError> {
        let head = chain.head();
        // The finalized root of the genesis checkpoint is zero on the wire.
        let finalized_root = if head.finalized.epoch == Epoch::GENESIS {
            Root::ZERO
        } else {
            head.finalized.root
        };
        Ok(Status {
            fork_digest: chain.fork_digest(chain.store().current_epoch()),
            finalized_root,
            finalized_epoch: head.finalized.epoch,
            head_root: head.root,
            head_slot: head.slot,
            earliest_available_slot: chain.database().earliest_slot()?.unwrap_or(head.slot),
        })
    }

    /// The metadata, as of now.
    fn metadata(&self) -> MetaData {
        let mut attnets = BitVector::default();
        for (index, subscribed) in self.metadata.attnets.iter().enumerate() {
            attnets.set(index, *subscribed);
        }
        MetaData {
            seq_number: self.metadata.seq_number.load(Ordering::Relaxed),
            attnets,
            syncnets: BitVector::default(),
            custody_group_count: self.metadata.custody_group_count,
        }
    }

    /// Canonical blocks in a slot range, oldest first.
    fn blocks_by_range(
        chain: &Chain<P>,
        request: BlocksByRangeRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let mut chunks = Vec::new();
        let count = request.count.min(MAX_BLOCKS);
        for slot in request.start_slot.0..request.start_slot.0.saturating_add(count) {
            // Empty slots have no block; the response just skips them.
            if let Some(root) = chain.canonical_root(Slot(slot))? {
                Self::push_block(chain, root, &mut chunks)?;
            }
        }
        Ok(chunks)
    }

    /// Blocks by root, in request order, skipping unknown ones.
    fn blocks_by_root(
        chain: &Chain<P>,
        request: &BlocksByRootRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let mut chunks = Vec::new();
        for root in request {
            Self::push_block(chain, *root, &mut chunks)?;
        }
        Ok(chunks)
    }

    /// A block and its ancestors, newest first.
    fn blocks_by_head(
        chain: &Chain<P>,
        request: BlocksByHeadRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let mut chunks = Vec::new();
        let mut root = request.beacon_root;
        let count = request.count.min(MAX_BLOCKS);
        while (chunks.len() as u64) < count {
            let Some(block) = chain.block(root)? else {
                break;
            };
            let parent = block.message.parent_root;
            chunks.push(Self::block_chunk(chain, &block));
            root = parent;
        }
        Ok(chunks)
    }

    /// Custody columns of canonical blocks in a slot range.
    fn columns_by_range(
        chain: &Chain<P>,
        request: &ColumnsByRangeRequest<P>,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let mut chunks = Vec::new();
        let count = request.count.min(MAX_BLOCKS);
        for slot in request.start_slot.0..request.start_slot.0.saturating_add(count) {
            if let Some(root) = chain.canonical_root(Slot(slot))? {
                Self::push_columns(chain, root, request.columns.iter().copied(), &mut chunks)?;
            }
        }
        Ok(chunks)
    }

    /// Columns by block root and index.
    fn columns_by_root(
        chain: &Chain<P>,
        request: &ColumnsByRootRequest<P>,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let mut chunks = Vec::new();
        for identifier in request {
            Self::push_columns(
                chain,
                identifier.block_root,
                identifier.columns.iter().copied(),
                &mut chunks,
            )?;
        }
        Ok(chunks)
    }

    /// Appends a stored block, if there is one.
    fn push_block(
        chain: &Chain<P>,
        root: Root,
        chunks: &mut Vec<ResponseChunk>,
    ) -> Result<(), ChainError> {
        if let Some(block) = chain.block(root)? {
            chunks.push(Self::block_chunk(chain, &block));
        }
        Ok(())
    }

    /// Appends the stored columns of a block among the indices asked for.
    fn push_columns(
        chain: &Chain<P>,
        root: Root,
        indices: impl Iterator<Item = ColumnIndex>,
        chunks: &mut Vec<ResponseChunk>,
    ) -> Result<(), ChainError> {
        for index in indices {
            // Only custody columns are stored; others are simply absent from the response.
            if let Some(column) = chain.database().column(root, index)? {
                let epoch = column.signed_block_header.message.slot.epoch::<P>();
                chunks.push(ResponseChunk::success(
                    Some(chain.fork_digest(epoch)),
                    column.encode(),
                ));
            }
        }
        Ok(())
    }

    /// A block as a response chunk, tagged with the digest of its fork.
    fn block_chunk(chain: &Chain<P>, block: &SignedBeaconBlock<P>) -> ResponseChunk {
        let epoch = block.message.slot.epoch::<P>();
        ResponseChunk::success(Some(chain.fork_digest(epoch)), block.encode())
    }

    /// Decodes a request body, or the error chunk for a malformed one.
    fn decode<T: Ssz>(payload: &[u8]) -> Result<T, ResponseChunk> {
        T::decode(payload)
            .map_err(|_| ResponseChunk::error(ResponseCode::InvalidRequest, "malformed request"))
    }

    /// The error chunk for a failure on this side.
    fn server_error(error: &ChainError) -> ResponseChunk {
        ResponseChunk::error(ResponseCode::ServerError, &error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Length;

    use super::*;
    use crate::network::requests::MaxRequestBlocks;

    #[test]
    fn the_served_block_limit_matches_the_request_list_bound() {
        assert_eq!(MaxRequestBlocks::LEN as u64, MAX_BLOCKS);
    }
}
