//! Blob data from the engine's blob pool: a block's columns built before peers send them.

use std::sync::Arc;

use axiom_das::BlockColumns;
use axiom_kzg::Kzg;
use axiom_p2p::{
    eth::{GossipKind, GossipTopic},
    swarm::NetworkHandle,
};
use axiom_types::{KzgCommitment, KzgProof, Preset, VersionedHash, combined, deneb::Blob};
use tokio::task;
use tracing::{debug, warn};

use crate::{ChainHandle, ExecutionLayer};

/// Fetches a new block's blobs from the engine, and builds the columns this node custodies.
///
/// # Overview
///
/// Blob transactions spread through the execution layer's mempool before their block exists.
/// The engine then often holds every blob a new block commits to.
/// Building the columns from those blobs makes the block available without waiting on peers.
///
/// 1. Once a block passes the gossip rules, ask the engine for its blobs by versioned hash.
/// 2. The engine answers with every blob and its cell proofs, or with nothing.
/// 3. Extend the blobs to cells, check every cell proof, and build the 128 column sidecars.
/// 4. Hand the custodied columns to the chain, as if they arrived on gossip.
/// 5. Publish those no peer had sent yet, so the network gets them sooner too.
///
/// Only blocks whose fork carries data in block columns use this, Fulu on.
/// The operator may turn it off, and a node without an engine never asks.
/// See `engine_getBlobsV2` in `src/engine/osaka.md` of the engine API.
#[derive(Clone, Debug)]
pub(crate) struct EngineBlobs<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine.
    execution: Arc<ExecutionLayer>,
    /// The network, for publishing.
    network: NetworkHandle,
}

impl<P: Preset> EngineBlobs<P> {
    /// A fetcher over the node's services.
    pub(crate) const fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        network: NetworkHandle,
    ) -> Self {
        Self {
            chain,
            execution,
            network,
        }
    }

    /// Fetches a block's blobs and hands its custodied columns over, when the engine has them all.
    pub(crate) async fn fetch(self, block: Arc<combined::SignedBeaconBlock<P>>) {
        let combined::SignedBeaconBlock::Fulu(signed) = block.as_ref() else {
            return;
        };
        let commitments = &signed.message.body.blob_kzg_commitments;
        if commitments.is_empty() {
            return;
        }
        let hashes: Vec<VersionedHash> = commitments
            .iter()
            .map(KzgCommitment::versioned_hash)
            .collect();
        let fork = block.fork_name();
        let Some(fetched) = self.execution.blobs::<P>(fork, &hashes).await else {
            return;
        };

        // A block imported meanwhile already has its columns.
        let root = block.block_root();
        let imported = self
            .chain
            .run(move |chain| chain.store().block_state(&root).is_some())
            .await;
        if !matches!(imported, Ok(false)) {
            return;
        }

        // Extending and checking 128 cells per blob is heavy, so it runs off the async workers.
        let blobs: Vec<Blob<P>> = fetched.iter().map(|entry| entry.blob.clone()).collect();
        let proofs: Vec<KzgProof> = fetched
            .iter()
            .flat_map(|entry| entry.proofs.iter().copied())
            .collect();
        let built = Arc::clone(&block);
        let columns = task::spawn_blocking(move || {
            let combined::SignedBeaconBlock::Fulu(signed) = built.as_ref() else {
                return Ok(Vec::new());
            };
            BlockColumns::new(signed).sidecars(&blobs, &proofs, Kzg::trusted())
        })
        .await;
        let columns = match columns {
            Ok(Ok(columns)) => columns,
            Ok(Err(error)) => {
                warn!(%root, %error, "engine blobs do not build the block's columns");
                return;
            }
            Err(_) => return,
        };

        let submitted = self
            .chain
            .run(move |chain| chain.submit_engine_columns(columns))
            .await;
        let fresh = match submitted {
            Ok(Ok(fresh)) => fresh,
            Ok(Err(error)) => {
                warn!(%root, %error, "columns from engine blobs not applied");
                return;
            }
            Err(_) => return,
        };
        debug!(%root, columns = fresh.len(), "columns built from engine blobs");
        self.publish(&fresh).await;
    }

    /// Publishes columns on their subnets.
    async fn publish(&self, columns: &[combined::DataColumnSidecar<P>]) {
        let Some(first) = columns.first() else {
            return;
        };
        let epoch = first.slot().epoch::<P>();
        let digests = self
            .chain
            .run(move |chain| {
                (
                    chain.fork_digest(epoch),
                    chain.config().data_column_sidecar_subnet_count,
                )
            })
            .await;
        let Ok((fork_digest, subnets)) = digests else {
            return;
        };
        for column in columns {
            let kind = GossipKind::DataColumnSidecar(column.index().0 % subnets.max(1));
            let topic = GossipTopic { fork_digest, kind };
            if let Err(error) = self.network.publish(topic.topic(), column.encode()).await {
                warn!(%error, "could not publish a column built from engine blobs");
            }
        }
    }
}
