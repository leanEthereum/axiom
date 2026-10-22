//! Catching up: fetching blocks and their columns from peers that are ahead.

use std::{collections::HashMap, sync::Arc};

use axiom_das::ColumnSidecar;
use axiom_kzg::Kzg;
use axiom_p2p::{
    PeerId,
    eth::reqresp::{Protocol, ResponseChunk, ResponseCode, Status},
    swarm::{NetworkError, NetworkHandle, RequestId},
};
use axiom_ssz::{List, Ssz};
use axiom_types::{ColumnIndex, DataColumnSidecar, Preset, SignedBeaconBlock, Slot};
use tracing::{debug, info, warn};

use super::requests::{BlocksByRangeRequest, ColumnsByRangeRequest};
use crate::{ChainHandle, ExecutionLayer};

/// Slots fetched per batch.
///
/// One epoch on mainnet: small enough to retry cheaply, large enough to amortize the round trip.
const BATCH_SLOTS: u64 = 32;

/// One range being fetched from one peer.
#[derive(Debug)]
struct Batch<P: Preset> {
    /// The peer serving it.
    peer: PeerId,
    /// The blocks request.
    blocks_request: RequestId,
    /// The columns request, when the node custodies any column.
    columns_request: Option<RequestId>,
    /// Requests still streaming.
    open: usize,
    /// Blocks received so far.
    blocks: Vec<SignedBeaconBlock<P>>,
    /// Columns received so far.
    columns: Vec<DataColumnSidecar<P>>,
}

/// Range sync: one batch in flight, from the best peer, until the node reaches the network's head.
///
/// # Overview
///
/// ```text
///     status from peers ──> best peer ahead of the head?
///                                   │ yes
///             blocks by range [head + 1, head + 32] + custody columns by range
///                                   │
///     columns: structure, inclusion proof, KZG ──> chain      blocks: engine verdict ──> chain
///                                   │
///                         next batch from the new head
/// ```
///
/// A peer serving an invalid batch is disconnected, and the batch restarts elsewhere.
/// Columns go in before blocks, so each block is available the moment it is submitted.
#[derive(Debug)]
pub(crate) struct RangeSync<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for judging payloads.
    execution: Arc<ExecutionLayer>,
    /// The network, for requests.
    network: NetworkHandle,
    /// Latest status of every connected peer.
    peers: HashMap<PeerId, Status>,
    /// The batch in flight, if any.
    batch: Option<Batch<P>>,
}

impl<P: Preset> RangeSync<P> {
    /// A sync with no peer yet.
    pub(crate) fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        network: NetworkHandle,
    ) -> Self {
        Self {
            chain,
            execution,
            network,
            peers: HashMap::new(),
            batch: None,
        }
    }

    /// Records a peer's status and starts a batch if the node is behind.
    pub(crate) async fn on_status(&mut self, peer: PeerId, status: Status) {
        self.peers.insert(peer, status);
        self.advance().await;
    }

    /// Forgets a peer, abandoning its batch.
    pub(crate) async fn on_disconnect(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
        if self.batch.as_ref().is_some_and(|batch| batch.peer == *peer) {
            self.batch = None;
            self.advance().await;
        }
    }

    /// Whether a request belongs to the batch in flight.
    pub(crate) fn owns(&self, request: RequestId) -> bool {
        self.batch.as_ref().is_some_and(|batch| {
            batch.blocks_request == request || batch.columns_request == Some(request)
        })
    }

    /// Takes one response chunk of the batch.
    pub(crate) fn on_chunk(&mut self, request: RequestId, chunk: &ResponseChunk) {
        let Some(batch) = &mut self.batch else {
            return;
        };
        if chunk.code != ResponseCode::Success {
            debug!(peer = %batch.peer, code = ?chunk.code, "batch request answered with an error");
            return;
        }
        // An undecodable chunk is dropped here; the batch then fails its checks and the peer goes.
        if request == batch.blocks_request {
            if let Ok(block) = SignedBeaconBlock::decode(&chunk.payload) {
                batch.blocks.push(block);
            }
        } else if let Ok(column) = DataColumnSidecar::decode(&chunk.payload) {
            batch.columns.push(column);
        }
    }

    /// Marks one of the batch's requests finished, processing the batch once both are.
    pub(crate) async fn on_end(&mut self, request: RequestId) {
        let Some(batch) = &mut self.batch else {
            return;
        };
        if batch.blocks_request == request || batch.columns_request == Some(request) {
            batch.open -= 1;
        }
        if batch.open == 0 {
            if let Some(batch) = self.batch.take() {
                self.process(batch).await;
            }
            self.advance().await;
        }
    }

    /// Abandons the batch after a failed request, and tries again.
    pub(crate) async fn on_failure(&mut self, request: RequestId) {
        if self.owns(request) {
            self.batch = None;
            self.advance().await;
        }
    }

    /// Starts the next batch if a peer is ahead and none is in flight.
    async fn advance(&mut self) {
        if self.batch.is_some() {
            return;
        }
        let Ok((head, custody)) = self
            .chain
            .run(|chain| {
                (
                    chain.head().slot,
                    chain.custody().iter().copied().collect::<Vec<_>>(),
                )
            })
            .await
        else {
            return;
        };
        // The peer furthest ahead serves the next batch.
        let Some((peer, status)) = self
            .peers
            .iter()
            .max_by_key(|(_, status)| status.head_slot)
            .map(|(peer, status)| (peer.clone(), *status))
        else {
            return;
        };
        if status.head_slot <= head {
            return;
        }
        let start = Slot(head.0 + 1);
        let count = BATCH_SLOTS.min(status.head_slot.0 - head.0);
        if let Err(error) = self.request(peer, start, count, custody) {
            warn!(%error, "could not request a batch");
        }
    }

    /// Sends the requests of a batch.
    fn request(
        &mut self,
        peer: PeerId,
        start: Slot,
        count: u64,
        custody: Vec<ColumnIndex>,
    ) -> Result<(), NetworkError> {
        let blocks = BlocksByRangeRequest {
            start_slot: start,
            count,
            step: 1,
        };
        let blocks_request = self.network.send_request(
            peer.clone(),
            Protocol::BeaconBlocksByRangeV2,
            blocks.encode(),
        )?;
        let columns_request = if custody.is_empty() {
            None
        } else {
            let columns = ColumnsByRangeRequest::<P> {
                start_slot: start,
                count,
                // Custody never exceeds the column count, so the list always fits.
                columns: List::try_from(custody).unwrap_or_default(),
            };
            Some(self.network.send_request(
                peer.clone(),
                Protocol::DataColumnSidecarsByRangeV1,
                columns.encode(),
            )?)
        };
        debug!(%peer, start = %start, count, "requested batch");
        self.batch = Some(Batch {
            peer,
            blocks_request,
            columns_request,
            open: 1 + usize::from(columns_request.is_some()),
            blocks: Vec::new(),
            columns: Vec::new(),
        });
        Ok(())
    }

    /// Verifies and imports a finished batch.
    async fn process(&mut self, batch: Batch<P>) {
        let Batch {
            peer,
            blocks,
            columns,
            ..
        } = batch;
        let count = blocks.len();

        // Columns first: each must be well formed, in its block, and open its commitments.
        let Ok(config) = self.chain.run(|chain| chain.config().clone()).await else {
            return;
        };
        for column in columns {
            let sidecar = ColumnSidecar(&column);
            let valid = sidecar.verify_structure(&config).is_ok()
                && sidecar.verify_inclusion_proof().is_ok()
                && sidecar.verify_kzg_proofs(Kzg::mainnet()).is_ok();
            if !valid {
                return self.punish(&peer, "invalid column in batch");
            }
            let column = Arc::new(column);
            if let Ok(Err(error)) = self
                .chain
                .run(move |chain| chain.submit_column(column))
                .await
            {
                return self.punish(&peer, &error.to_string());
            }
        }

        // Then blocks, in order: each extends the one before.
        for block in blocks {
            let block = Arc::new(block);
            let payload = self.execution.verdict(&block.message).await;
            match self
                .chain
                .run(move |chain| chain.submit_block(block, payload))
                .await
            {
                Ok(Ok(_)) | Err(_) => {}
                Ok(Err(error)) => return self.punish(&peer, &error.to_string()),
            }
        }
        if count > 0 {
            info!(%peer, blocks = count, "synced batch");
        }
    }

    /// Drops a peer that served bad data.
    fn punish(&mut self, peer: &PeerId, reason: &str) {
        warn!(%peer, reason, "disconnecting peer for a bad batch");
        self.peers.remove(peer);
        // A disconnect only fails when the network is gone, which ends sync anyway.
        let _stopped = self.network.disconnect(peer.clone());
    }
}
