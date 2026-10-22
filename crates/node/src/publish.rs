//! Publishing a block a validator proposed: check it, gossip it with its columns, import it.

use std::sync::Arc;

use axiom_das::{BlockColumns, ColumnError};
use axiom_gossip::GossipError;
use axiom_kzg::Kzg;
use axiom_p2p::{
    eth::{GossipKind, GossipTopic},
    swarm::NetworkHandle,
};
use axiom_ssz::Ssz;
use axiom_types::{DataColumnSidecar, Preset, Root, SignedBeaconBlock, SignedBlockContents};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{ChainError, ChainHandle, Clock, ExecutionLayer};

/// What happened to a published block.
#[derive(Debug)]
pub enum Published {
    /// Gossiped and imported.
    Imported(Root),
    /// Gossiped, but this node's own import failed.
    BroadcastOnly(ChainError),
}

/// Why a block was not published at all.
#[derive(Debug, Error)]
pub enum PublishError {
    /// The blobs or proofs do not match the block's commitments.
    #[error("blob data: {0}")]
    Columns(#[source] ColumnError),
    /// The block breaks a gossip rule, so peers would reject it.
    #[error("invalid block: {0}")]
    Invalid(#[source] GossipError),
    /// The chain thread has stopped.
    #[error("chain service stopped")]
    ChainStopped,
}

/// Publishes proposed blocks.
///
/// # Overview
///
/// ```text
///     block + blobs + cell proofs
///          │
///          ├── build the 128 column sidecars, checking every cell proof
///          ├── gossip rules for blocks: a rejected block is never broadcast
///          ├── broadcast the block, then each column on its subnet
///          └── import: custody columns first, then the block with its engine verdict
/// ```
///
/// See `publishBlockV2` in the beacon API, with gossip-level broadcast validation.
#[derive(Debug)]
pub struct Publisher<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for the payload verdict.
    execution: Arc<ExecutionLayer>,
    /// The wall clock the gossip rules read.
    clock: Arc<dyn Clock>,
    /// The network, when the node has one.
    network: Option<NetworkHandle>,
}

impl<P: Preset> Publisher<P> {
    /// A publisher over the node's services.
    pub fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        clock: Arc<dyn Clock>,
        network: Option<NetworkHandle>,
    ) -> Self {
        Self {
            chain,
            execution,
            clock,
            network,
        }
    }

    /// Publishes a block with its blobs.
    ///
    /// # Errors
    ///
    /// Fails, broadcasting nothing, when the blob data is wrong or the block breaks a gossip rule.
    pub async fn publish(
        &self,
        contents: SignedBlockContents<P>,
    ) -> Result<Published, PublishError> {
        let SignedBlockContents {
            signed_block,
            kzg_proofs,
            blobs,
        } = contents;
        let block = Arc::new(signed_block);

        // A block without blobs has no columns; one with blobs needs all 128.
        let sidecars = if block.message.body.blob_kzg_commitments.is_empty() {
            Vec::new()
        } else {
            BlockColumns::new(&block)
                .sidecars(&blobs, &kzg_proofs, Kzg::mainnet())
                .map_err(PublishError::Columns)?
        };

        // The block must pass the rules peers apply, or broadcasting it would cost reputation.
        let now = self.clock.now_ms();
        let checked = Arc::clone(&block);
        let verdict = self
            .chain
            .run(move |chain| {
                chain.validate_gossip(|validator| validator.beacon_block(&checked, now))
            })
            .await
            .map_err(|_| PublishError::ChainStopped)?;
        match verdict {
            Ok(()) => {}
            Err(error @ GossipError::Reject { .. }) => return Err(PublishError::Invalid(error)),
            // An ignored block, such as one already seen, is still broadcast and imported.
            Err(error @ GossipError::Ignore { .. }) => {
                debug!(%error, "published block ignored by gossip rules");
            }
        }

        self.broadcast(&block, &sidecars).await?;
        Ok(self.import(block, sidecars).await)
    }

    /// Gossips the block, then each column on its subnet.
    async fn broadcast(
        &self,
        block: &SignedBeaconBlock<P>,
        sidecars: &[DataColumnSidecar<P>],
    ) -> Result<(), PublishError> {
        let Some(network) = &self.network else {
            return Ok(());
        };
        let epoch = block.message.slot.epoch::<P>();
        let (fork_digest, subnet_count) = self
            .chain
            .run(move |chain| {
                (
                    chain.fork_digest(epoch),
                    chain.config().data_column_sidecar_subnet_count,
                )
            })
            .await
            .map_err(|_| PublishError::ChainStopped)?;

        // The block goes first: peers check columns against a header they may already hold.
        let topic = GossipTopic {
            fork_digest,
            kind: GossipKind::BeaconBlock,
        };
        if let Err(error) = network.publish(topic.topic(), block.encode()).await {
            warn!(%error, "could not broadcast the block");
        }
        for sidecar in sidecars {
            let topic = GossipTopic {
                fork_digest,
                kind: GossipKind::DataColumnSidecar(sidecar.index.0 % subnet_count),
            };
            if let Err(error) = network.publish(topic.topic(), sidecar.encode()).await {
                warn!(%error, column = sidecar.index.0, "could not broadcast a column");
            }
        }
        Ok(())
    }

    /// Imports the block, its custody columns first so it is available at once.
    async fn import(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        sidecars: Vec<DataColumnSidecar<P>>,
    ) -> Published {
        let payload = self.execution.verdict(&block.message).await;
        let outcome = self
            .chain
            .run(move |chain| {
                // Columns outside custody are dropped by the chain; it keeps what it samples.
                for sidecar in sidecars {
                    chain.submit_column(Arc::new(sidecar))?;
                }
                chain.submit_block(block, payload)
            })
            .await;
        match outcome {
            Ok(Ok(submission)) => {
                info!(?submission, "published block");
                Published::Imported(submission.root())
            }
            Ok(Err(error)) => Published::BroadcastOnly(error),
            Err(_) => Published::BroadcastOnly(ChainError::Stopped),
        }
    }
}
