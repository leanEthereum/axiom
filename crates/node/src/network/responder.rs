//! Answers built from one chain query: the node's status, and block and column chunks.

use std::collections::BTreeSet;

use axiom_p2p::eth::reqresp::{ResponseChunk, ResponseCode, Status};
use axiom_ssz::Ssz;
use axiom_types::{ColumnIndex, Epoch, Preset, Root, SignedBeaconBlock, Slot};

use super::requests::{
    BlocksByHeadRequest, BlocksByRangeRequest, BlocksByRootRequest, ColumnsByRangeRequest,
    ColumnsByRootRequest,
};
use crate::{Chain, ChainError};

/// Most blocks served for one request: MAX_REQUEST_BLOCKS_DENEB.
const MAX_BLOCKS: u64 = 128;

/// The chain as one request sees it, and the chunks answered so far.
///
/// It lives inside a single chain query, so a request never sees a half-applied block.
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
        let count = request.count.min(MAX_BLOCKS);
        for slot in request.start_slot.0..request.start_slot.0.saturating_add(count) {
            // Empty slots have no block; the response just skips them.
            if let Some(root) = self.chain.canonical_root(Slot(slot))? {
                self.push_block(root)?;
            }
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
            let parent = block.message.parent_root;
            self.chunks.push(self.block_chunk(&block));
            root = parent;
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
        let count = request.count.min(MAX_BLOCKS);
        for slot in request.start_slot.0..request.start_slot.0.saturating_add(count) {
            if let Some(root) = self.chain.canonical_root(Slot(slot))? {
                self.push_columns(root, request.columns.iter().copied())?;
            }
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
            self.push_columns(identifier.block_root, identifier.columns.iter().copied())?;
        }
        Ok(self.chunks)
    }

    /// Appends a stored block, if there is one.
    fn push_block(&mut self, root: Root) -> Result<(), ChainError> {
        if let Some(block) = self.chain.block(root)? {
            let chunk = self.block_chunk(&block);
            self.chunks.push(chunk);
        }
        Ok(())
    }

    /// Appends the stored columns of a block among the indices asked for.
    fn push_columns(
        &mut self,
        root: Root,
        indices: impl Iterator<Item = ColumnIndex>,
    ) -> Result<(), ChainError> {
        // Responses list a block's columns once each, in index order, as the spec requires.
        let indices: BTreeSet<ColumnIndex> = indices.collect();
        for index in indices {
            // Only custody columns are stored; others are simply absent from the response.
            if let Some(column) = self.chain.database().column(root, index)? {
                let epoch = column.signed_block_header.message.slot.epoch::<P>();
                self.chunks.push(ResponseChunk::success(
                    Some(self.chain.fork_digest(epoch)),
                    column.encode(),
                ));
            }
        }
        Ok(())
    }

    /// A block as a response chunk, tagged with the digest of its fork.
    fn block_chunk(&self, block: &SignedBeaconBlock<P>) -> ResponseChunk {
        let epoch = block.message.slot.epoch::<P>();
        ResponseChunk::success(Some(self.chain.fork_digest(epoch)), block.encode())
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
    use crate::network::requests::MaxRequestBlocks;

    #[test]
    fn the_served_block_limit_matches_the_request_list_bound() {
        assert_eq!(MaxRequestBlocks::LEN as u64, MAX_BLOCKS);
    }
}
