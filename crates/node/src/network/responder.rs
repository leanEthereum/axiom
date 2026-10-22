//! Answers built from one chain query: the node's status, and chunks of blocks and their data.

use std::collections::BTreeSet;

use axiom_p2p::eth::reqresp::{ResponseChunk, ResponseCode, Status};
use axiom_ssz::Ssz;
use axiom_types::{BlobIndex, ColumnIndex, Epoch, Preset, Root, Slot, deneb::BlobIdentifier};

use super::requests::{
    BlobsByRootRequest, BlocksByHeadRequest, BlocksByRangeRequest, BlocksByRootRequest,
    ColumnsByRangeRequest, ColumnsByRootRequest, EnvelopesByRootRequest, SlotRangeRequest,
    UpdatesByRangeRequest,
};
use crate::{Chain, ChainError};

/// Most blocks served for one request: MAX_REQUEST_BLOCKS_DENEB.
const MAX_BLOCKS: u64 = 128;

/// Most blob sidecars served for one request: MAX_REQUEST_BLOB_SIDECARS_ELECTRA.
const MAX_BLOBS: usize = 1152;

/// The chain as one request sees it, and the chunks answered so far.
///
/// It lives inside a single chain query, so a request never sees a half-applied block.
/// Each chunk carries the digest of the fork its item belongs to, so peers decode it right.
#[derive(Debug)]
pub(crate) struct Responder<'a, P: Preset> {
    /// The chain, on its own thread.
    chain: &'a Chain<P>,
    /// The chunks answered so far.
    chunks: Vec<ResponseChunk>,
}

impl<'a, P: Preset> Responder<'a, P> {
    /// A responder with nothing answered yet.
    pub(crate) const fn new(chain: &'a Chain<P>) -> Self {
        Self {
            chain,
            chunks: Vec::new(),
        }
    }

    /// The node's status, as the handshake sends it.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn status(self) -> Result<Status, ChainError> {
        let chain = self.chain;
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

    /// Canonical blocks in a slot range, oldest first.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn blocks_by_range(
        mut self,
        request: BlocksByRangeRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for (_, root) in self.canonical(request.start_slot, request.count)? {
            self.push_block(root)?;
        }
        Ok(self.chunks)
    }

    /// Blocks by root, in request order, skipping unknown ones.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn blocks_by_root(
        mut self,
        request: &BlocksByRootRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for root in request {
            self.push_block(*root)?;
        }
        Ok(self.chunks)
    }

    /// A block and its ancestors, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn blocks_by_head(
        mut self,
        request: BlocksByHeadRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let mut root = request.beacon_root;
        let count = request.count.min(MAX_BLOCKS);
        while (self.chunks.len() as u64) < count {
            let Some(block) = self.chain.block(root)? else {
                break;
            };
            root = block.parent_root();
            self.chunks.push(self.chunk(block.slot(), block.encode()));
        }
        Ok(self.chunks)
    }

    /// Blob sidecars of canonical blocks in a slot range, by block then index.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn blobs_by_range(
        mut self,
        request: SlotRangeRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for (slot, root) in self.canonical(request.start_slot, request.count)? {
            // A block's blob indices run from zero; the first gap ends its sidecars.
            for index in 0.. {
                if self.chunks.len() >= MAX_BLOBS {
                    return Ok(self.chunks);
                }
                let Some(blob) = self.chain.database().blob(root, BlobIndex(index))? else {
                    break;
                };
                self.chunks.push(self.chunk(slot, blob.encode()));
            }
        }
        Ok(self.chunks)
    }

    /// Blob sidecars by block root and index, skipping unknown ones.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn blobs_by_root(
        mut self,
        request: &BlobsByRootRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for BlobIdentifier { block_root, index } in request {
            if let Some(blob) = self.chain.database().blob(*block_root, *index)? {
                let slot = blob.signed_block_header.message.slot;
                self.chunks.push(self.chunk(slot, blob.encode()));
            }
        }
        Ok(self.chunks)
    }

    /// Custody columns of canonical blocks in a slot range.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn columns_by_range(
        mut self,
        request: &ColumnsByRangeRequest<P>,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for (slot, root) in self.canonical(request.start_slot, request.count)? {
            self.push_columns(root, slot, request.columns.iter().copied())?;
        }
        Ok(self.chunks)
    }

    /// Columns by block root and index.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn columns_by_root(
        mut self,
        request: &ColumnsByRootRequest<P>,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for identifier in request {
            // The block's slot fixes the column format; an unknown block has no columns.
            if let Some(slot) = self.chain.block_slot(identifier.block_root)? {
                self.push_columns(
                    identifier.block_root,
                    slot,
                    identifier.columns.iter().copied(),
                )?;
            }
        }
        Ok(self.chunks)
    }

    /// Payload envelopes of the canonical chain in a slot range.
    ///
    /// A payload is on the chain when the next canonical block builds on it.
    /// The newest block's payload counts whenever the node imported it.
    /// See `ExecutionPayloadEnvelopesByRange v1` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn envelopes_by_range(
        mut self,
        request: SlotRangeRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        let blocks = self.canonical(request.start_slot, request.count)?;
        // The block after the range decides whether the range's last payload is canonical.
        let end = request.start_slot.0.saturating_add(request.count);
        let successor =
            self.canonical(Slot(end), self.chain.head().slot.0.saturating_sub(end) + 1)?;
        let mut next_blocks = blocks.iter().skip(1).chain(successor.iter().take(1));
        for (slot, root) in &blocks {
            let next = next_blocks.next();
            let Some(envelope) = self.chain.database().envelope(*root)? else {
                continue;
            };
            let canonical = match next {
                Some((_, next_root)) => self.chain.block(*next_root)?.is_some_and(|block| {
                    block.message().execution_hashes().parent_block_hash
                        == envelope.message.payload.block_hash
                }),
                None => true,
            };
            if canonical {
                self.chunks.push(self.chunk(*slot, envelope.encode()));
            }
        }
        Ok(self.chunks)
    }

    /// Payload envelopes by block root, skipping unknown ones.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn envelopes_by_root(
        mut self,
        request: &EnvelopesByRootRequest,
    ) -> Result<Vec<ResponseChunk>, ChainError> {
        for root in request {
            if let Some(envelope) = self.chain.database().envelope(*root)?
                && let Some(slot) = self.chain.block_slot(*root)?
            {
                self.chunks.push(self.chunk(slot, envelope.encode()));
            }
        }
        Ok(self.chunks)
    }

    /// The light client bootstrap of a block, if the node offers one.
    ///
    /// See `GetLightClientBootstrap` in the Altair light client networking spec.
    pub(crate) fn light_client_bootstrap(mut self, root: &Root) -> Vec<ResponseChunk> {
        if let Some(bootstrap) = self.chain.light_client().bootstrap(root) {
            let chunk = self.chunk(bootstrap.context_slot(), bootstrap.encode());
            self.chunks.push(chunk);
        }
        self.chunks
    }

    /// The best light client updates of consecutive periods.
    ///
    /// See `LightClientUpdatesByRange` in the Altair light client networking spec.
    pub(crate) fn light_client_updates(
        mut self,
        request: UpdatesByRangeRequest,
    ) -> Vec<ResponseChunk> {
        let light_client = self.chain.light_client();
        for update in light_client.updates_by_range(request.start_period, request.count) {
            let chunk = self.chunk(update.context_slot(), update.encode());
            self.chunks.push(chunk);
        }
        self.chunks
    }

    /// The latest light client finality update, if any.
    ///
    /// See `GetLightClientFinalityUpdate` in the Altair light client networking spec.
    pub(crate) fn light_client_finality_update(mut self) -> Vec<ResponseChunk> {
        if let Some(update) = self.chain.light_client().latest_finality_update() {
            let chunk = self.chunk(update.context_slot(), update.encode());
            self.chunks.push(chunk);
        }
        self.chunks
    }

    /// The latest light client optimistic update, if any.
    ///
    /// See `GetLightClientOptimisticUpdate` in the Altair light client networking spec.
    pub(crate) fn light_client_optimistic_update(mut self) -> Vec<ResponseChunk> {
        if let Some(update) = self.chain.light_client().latest_optimistic_update() {
            let chunk = self.chunk(update.context_slot(), update.encode());
            self.chunks.push(chunk);
        }
        self.chunks
    }

    /// Slots and roots of the canonical blocks in a range, capped at the served block count.
    fn canonical(&self, start: Slot, count: u64) -> Result<Vec<(Slot, Root)>, ChainError> {
        let count = count.min(MAX_BLOCKS);
        let mut blocks = Vec::new();
        for slot in start.0..start.0.saturating_add(count) {
            // Empty slots have no block; the response just skips them.
            if let Some(root) = self.chain.canonical_root(Slot(slot))? {
                blocks.push((Slot(slot), root));
            }
        }
        Ok(blocks)
    }

    /// Appends a stored block, if there is one.
    fn push_block(&mut self, root: Root) -> Result<(), ChainError> {
        if let Some(block) = self.chain.block(root)? {
            let chunk = self.chunk(block.slot(), block.encode());
            self.chunks.push(chunk);
        }
        Ok(())
    }

    /// Appends the stored columns of a block among the indices asked for.
    fn push_columns(
        &mut self,
        root: Root,
        slot: Slot,
        indices: impl Iterator<Item = ColumnIndex>,
    ) -> Result<(), ChainError> {
        let fork = self.chain.config().fork_at(slot.epoch::<P>());
        // Responses list a block's columns once each, in index order, as the spec requires.
        let indices: BTreeSet<ColumnIndex> = indices.collect();
        for index in indices {
            // Only custody columns are stored; others are simply absent from the response.
            if let Some(column) = self.chain.database().column(root, index, fork)? {
                let chunk = self.chunk(slot, column.encode());
                self.chunks.push(chunk);
            }
        }
        Ok(())
    }

    /// An item of a block's slot as a response chunk, tagged with the digest of that slot's fork.
    fn chunk(&self, slot: Slot, ssz: Vec<u8>) -> ResponseChunk {
        ResponseChunk::success(Some(self.chain.fork_digest(slot.epoch::<P>())), ssz)
    }
}

/// The body of an inbound request, before decoding.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestBody<'a>(pub(crate) &'a [u8]);

impl RequestBody<'_> {
    /// Decodes the body, or the error chunk for a malformed one.
    ///
    /// # Errors
    ///
    /// Fails with an invalid request chunk when the body does not decode.
    pub(crate) fn decode<T: Ssz>(self) -> Result<T, ResponseChunk> {
        T::decode(self.0)
            .map_err(|_| ResponseChunk::error(ResponseCode::InvalidRequest, "malformed request"))
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Length;

    use super::*;
    use crate::network::requests::{MaxRequestBlobSidecars, MaxRequestBlocks};

    #[test]
    fn the_served_limits_match_the_request_list_bounds() {
        assert_eq!(MaxRequestBlocks::LEN as u64, MAX_BLOCKS);
        assert_eq!(MaxRequestBlobSidecars::LEN, MAX_BLOBS);
    }
}
