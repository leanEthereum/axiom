//! Publishing a block a validator proposed: check it, gossip it with its data, import it.

use std::sync::Arc;

use axiom_das::{BlockColumns, ColumnError};
use axiom_gossip::GossipError;
use axiom_kzg::Kzg;
use axiom_p2p::{
    eth::{GossipKind, GossipTopic},
    swarm::NetworkHandle,
};
use axiom_ssz::Ssz;
use axiom_types::{
    BlobData, ForkName, Preset, Root, Slot, combined,
    fulu::{DataColumnSidecar, SignedBlockContents},
    gloas::SignedExecutionPayloadEnvelope,
};
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
    /// The block commits to blobs whose sidecars this node cannot build.
    #[error("{fork} block commits to {count} blobs, but only Fulu blobs can be published")]
    BlobsUnsupported {
        /// The block's fork.
        fork: ForkName,
        /// Blobs the block commits to.
        count: usize,
    },
    /// The block or envelope breaks a gossip rule, so peers would reject it.
    #[error("invalid block: {0}")]
    Invalid(#[source] GossipError),
    /// The chain thread has stopped.
    #[error("chain service stopped")]
    ChainStopped,
}

/// A proposed block with the blob data that travels beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal<P: Preset> {
    /// A block alone, whose blob data, if any, is not part of the proposal.
    ///
    /// Gloas blocks are proposed alone: their blobs follow with the payload envelope.
    Block(combined::SignedBeaconBlock<P>),
    /// A Fulu block with its blobs and cell proofs, from which every column is built.
    Columns(SignedBlockContents<P>),
}

impl<P: Preset> Proposal<P> {
    /// Slot of the proposed block.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Block(block) => block.slot(),
            Self::Columns(contents) => contents.signed_block.message.slot,
        }
    }
}

/// Publishes proposed blocks.
///
/// # Overview
///
/// A block arrives alone or with its blobs, and publishing runs four steps:
///
/// 1. Build the column sidecars from the blobs, checking every cell proof.
/// 2. Apply the gossip rules for blocks, so a rejected block is never broadcast.
/// 3. Broadcast the block, then each column on its subnet.
/// 4. Import the custody columns first, then the block with its engine verdict.
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

    /// Publishes a block with its blob data.
    ///
    /// # Errors
    ///
    /// Fails, broadcasting nothing, when the blob data is wrong or the block breaks a gossip rule.
    pub async fn publish(&self, proposal: Proposal<P>) -> Result<Published, PublishError> {
        let (block, sidecars) = Self::with_columns(proposal)?;
        let block = Arc::new(block);

        // The block must pass the rules peers apply, or broadcasting it would cost reputation.
        let now = self.clock.now_ms();
        let checked = Arc::clone(&block);
        let verdict = self
            .chain
            .run(move |chain| {
                chain.validate_gossip(|validator| validator.any_beacon_block(&checked, now))
            })
            .await
            .map_err(|_| PublishError::ChainStopped)?;
        Self::screen(verdict)?;

        self.broadcast(&block, &sidecars).await?;
        Ok(self.import(block, sidecars).await)
    }

    /// Publishes the payload envelope a Gloas block's builder revealed.
    ///
    /// The envelope passes the gossip rules, goes out on its topic, then imports.
    /// See `validate_execution_payload_envelope_gossip` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Fails, broadcasting nothing, when the envelope breaks a gossip rule.
    pub async fn publish_envelope(
        &self,
        envelope: SignedExecutionPayloadEnvelope<P>,
    ) -> Result<Published, PublishError> {
        let envelope = Arc::new(envelope);
        let checked = Arc::clone(&envelope);
        let verdict = self
            .chain
            .run(move |chain| {
                chain.validate_gossip(|validator| validator.execution_payload_envelope(&checked))
            })
            .await
            .map_err(|_| PublishError::ChainStopped)?;
        Self::screen(verdict)?;

        if let Some(network) = &self.network {
            let epoch = Slot(envelope.message.payload.slot_number).epoch::<P>();
            let fork_digest = self
                .chain
                .run(move |chain| chain.fork_digest(epoch))
                .await
                .map_err(|_| PublishError::ChainStopped)?;
            let topic = GossipTopic {
                fork_digest,
                kind: GossipKind::ExecutionPayload,
            };
            if let Err(error) = network.publish(topic.topic(), envelope.encode()).await {
                warn!(%error, "could not broadcast the payload envelope");
            }
        }

        let payload = self.execution.judge_envelope(&self.chain, &envelope).await;
        let outcome = self
            .chain
            .run(move |chain| chain.submit_envelope(envelope, payload))
            .await;
        Ok(match outcome {
            Ok(Ok(submission)) => {
                info!(?submission, "published payload envelope");
                Published::Imported(submission.root())
            }
            Ok(Err(error)) => Published::BroadcastOnly(error),
            Err(_) => Published::BroadcastOnly(ChainError::Stopped),
        })
    }

    /// Stops what peers would reject; what they would only ignore still goes out.
    fn screen(verdict: Result<(), GossipError>) -> Result<(), PublishError> {
        match verdict {
            Ok(()) => Ok(()),
            Err(error @ GossipError::Reject { .. }) => Err(PublishError::Invalid(error)),
            // An ignored message, such as one already seen, is still broadcast and imported.
            Err(error @ GossipError::Ignore { .. }) => {
                debug!(%error, "published message ignored by gossip rules");
                Ok(())
            }
        }
    }

    /// The block and the columns its blobs extend to, or none when the block has no blob here.
    fn with_columns(
        proposal: Proposal<P>,
    ) -> Result<(combined::SignedBeaconBlock<P>, Vec<DataColumnSidecar<P>>), PublishError> {
        match proposal {
            Proposal::Columns(contents) => {
                let SignedBlockContents {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = contents;
                // A block without blobs has no columns; one with blobs needs all of them.
                let sidecars = if signed_block.message.body.blob_kzg_commitments.is_empty() {
                    Vec::new()
                } else {
                    BlockColumns::new(&signed_block)
                        .sidecars(&blobs, &kzg_proofs, Kzg::mainnet())
                        .map_err(PublishError::Columns)?
                };
                Ok((combined::SignedBeaconBlock::Fulu(signed_block), sidecars))
            }
            Proposal::Block(block) => {
                // Blob sidecars of Deneb and Electra, and Fulu's columns, need the blobs at hand.
                let count = block.message().blob_kzg_commitments().len();
                let fork = block.fork_name();
                let needs_blobs = matches!(
                    fork.blob_data(),
                    BlobData::BlobSidecars | BlobData::BlockColumns
                );
                if needs_blobs && count > 0 {
                    return Err(PublishError::BlobsUnsupported { fork, count });
                }
                Ok((block, Vec::new()))
            }
        }
    }

    /// Gossips the block, then each column on its subnet.
    async fn broadcast(
        &self,
        block: &combined::SignedBeaconBlock<P>,
        sidecars: &[DataColumnSidecar<P>],
    ) -> Result<(), PublishError> {
        let Some(network) = &self.network else {
            return Ok(());
        };
        let epoch = block.slot().epoch::<P>();
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
        block: Arc<combined::SignedBeaconBlock<P>>,
        sidecars: Vec<DataColumnSidecar<P>>,
    ) -> Published {
        let payload = self.execution.verdict(&block).await;
        let outcome = self
            .chain
            .run(move |chain| {
                // Columns outside custody are dropped by the chain; it keeps what it samples.
                for sidecar in sidecars {
                    chain.submit_column(Arc::new(sidecar.into()))?;
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
