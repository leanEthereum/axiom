//! Publishing a block a validator proposed: check it, gossip it with its data, import it.

use std::sync::Arc;

use axiom_das::{BlockColumns, ColumnError};
use axiom_gossip::{BlobError, BlobSubnets, BlockBlobs, GossipError};
use axiom_kzg::Kzg;
use axiom_p2p::{
    eth::{GossipKind, GossipTopic},
    swarm::NetworkHandle,
};
use axiom_ssz::{DecodeError, Ssz};
use axiom_types::{
    BlobData, ChainConfig, Epoch, ForkName, Preset, Root, Slot, combined,
    deneb::{self, BlobSidecar},
    electra,
    fulu::{self, DataColumnSidecar},
    gloas::SignedExecutionPayloadEnvelope,
};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{Chain, ChainError, ChainHandle, Clock, ExecutionLayer};

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
    /// The blobs or cell proofs do not match the block's commitments.
    #[error("blob data: {0}")]
    Columns(#[source] ColumnError),
    /// The blobs or blob proofs do not match the block's commitments.
    #[error("blob data: {0}")]
    Blobs(#[source] BlobError),
    /// The block commits to blobs, but they do not travel with it.
    #[error("{fork} block {block_root} commits to {count} blobs, but none travel with it")]
    BlobsMissing {
        /// The block's fork.
        fork: ForkName,
        /// Root of the block.
        block_root: Root,
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
    /// Blocks before Deneb have no blobs.
    /// Gloas blocks are proposed alone: their blobs follow with the payload envelope.
    Block(combined::SignedBeaconBlock<P>),
    /// A Deneb block with its blobs and one proof per blob.
    DenebBlobs(deneb::SignedBlockContents<P>),
    /// An Electra block with its blobs and one proof per blob.
    ElectraBlobs(electra::SignedBlockContents<P>),
    /// A Fulu block with its blobs and cell proofs, from which every column is built.
    Columns(fulu::SignedBlockContents<P>),
}

impl<P: Preset> Proposal<P> {
    /// Decodes the body of the publish-block route in the format of a fork.
    ///
    /// From Deneb to Fulu the body bundles the block with its blobs.
    /// Before Deneb, and from Gloas on, the body is the block alone.
    /// See `publishBlockV2` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not that fork's body.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        Ok(match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Gloas => Self::Block(combined::SignedBeaconBlock::decode(bytes, fork)?),
            ForkName::Deneb => Self::DenebBlobs(Ssz::decode(bytes)?),
            ForkName::Electra => Self::ElectraBlobs(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Columns(Ssz::decode(bytes)?),
        })
    }

    /// Slot of the proposed block.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Block(block) => block.slot(),
            Self::DenebBlobs(contents) => contents.signed_block.message.slot,
            Self::ElectraBlobs(contents) => contents.signed_block.message.slot,
            Self::Columns(contents) => contents.signed_block.message.slot,
        }
    }
}

/// The sidecars that carry a published block's blobs.
#[derive(Debug)]
enum Sidecars<P: Preset> {
    /// No blob travels beside the block.
    None,
    /// One sidecar per blob.
    Blobs {
        /// The sidecars, in blob order.
        sidecars: Vec<BlobSidecar<P>>,
        /// The subnet limits of the block's fork, read from the chain configuration.
        subnets: fn(&ChainConfig) -> BlobSubnets,
    },
    /// One sidecar per column.
    Columns(Vec<DataColumnSidecar<P>>),
}

impl<P: Preset> Sidecars<P> {
    /// Each sidecar's gossip topic and encoding.
    ///
    /// See `compute_subnet_for_blob_sidecar` in the Deneb and Electra validator specs.
    /// See `compute_subnet_for_data_column_sidecar` in the Fulu validator spec.
    fn messages(&self, config: &ChainConfig) -> Vec<(GossipKind, Vec<u8>)> {
        match self {
            Self::None => Vec::new(),
            Self::Blobs { sidecars, subnets } => {
                let subnets = subnets(config);
                sidecars
                    .iter()
                    .map(|sidecar| {
                        let kind = GossipKind::BlobSidecar(subnets.subnet(sidecar.index));
                        (kind, sidecar.encode())
                    })
                    .collect()
            }
            Self::Columns(sidecars) => sidecars
                .iter()
                .map(|sidecar| {
                    let subnet = sidecar.index.0 % config.data_column_sidecar_subnet_count;
                    (GossipKind::DataColumnSidecar(subnet), sidecar.encode())
                })
                .collect(),
        }
    }

    /// Hands every sidecar to the chain, so the block that follows is available at once.
    fn submit(self, chain: &mut Chain<P>) -> Result<(), ChainError> {
        match self {
            Self::None => {}
            Self::Blobs { sidecars, .. } => {
                for sidecar in sidecars {
                    chain.submit_blob(Arc::new(sidecar))?;
                }
            }
            // Columns outside custody are dropped by the chain; it keeps what it samples.
            Self::Columns(sidecars) => {
                for sidecar in sidecars {
                    chain.submit_column(Arc::new(sidecar.into()))?;
                }
            }
        }
        Ok(())
    }
}

/// Publishes proposed blocks.
///
/// # Overview
///
/// A block arrives alone or with its blobs, and publishing runs four steps:
///
/// 1. Build the blob or column sidecars from the blobs, checking every proof.
/// 2. Apply the gossip rules for blocks, so a rejected block is never broadcast.
/// 3. Broadcast the block, then each sidecar on its subnet.
/// 4. Import the sidecars first, then the block with its engine verdict.
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
        let (block, sidecars) = Self::with_sidecars(proposal)?;
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

    /// The block and the sidecars that carry its blobs.
    fn with_sidecars(
        proposal: Proposal<P>,
    ) -> Result<(combined::SignedBeaconBlock<P>, Sidecars<P>), PublishError> {
        match proposal {
            Proposal::DenebBlobs(contents) => {
                let sidecars = BlockBlobs::deneb(&contents.signed_block)
                    .sidecars(&contents.blobs, &contents.kzg_proofs, Kzg::mainnet())
                    .map_err(PublishError::Blobs)?;
                let sidecars = Sidecars::Blobs {
                    sidecars,
                    subnets: BlobSubnets::deneb,
                };
                let block = combined::SignedBeaconBlock::Deneb(contents.signed_block);
                Ok((block, sidecars))
            }
            Proposal::ElectraBlobs(contents) => {
                let sidecars = BlockBlobs::electra(&contents.signed_block)
                    .sidecars(&contents.blobs, &contents.kzg_proofs, Kzg::mainnet())
                    .map_err(PublishError::Blobs)?;
                let sidecars = Sidecars::Blobs {
                    sidecars,
                    subnets: BlobSubnets::electra,
                };
                let block = combined::SignedBeaconBlock::Electra(contents.signed_block);
                Ok((block, sidecars))
            }
            Proposal::Columns(contents) => {
                let fulu::SignedBlockContents {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = contents;
                // A block without blobs has no columns; one with blobs needs all of them.
                let sidecars = if signed_block.message.body.blob_kzg_commitments.is_empty() {
                    Sidecars::None
                } else {
                    let columns = BlockColumns::new(&signed_block)
                        .sidecars(&blobs, &kzg_proofs, Kzg::mainnet())
                        .map_err(PublishError::Columns)?;
                    Sidecars::Columns(columns)
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
                    return Err(PublishError::BlobsMissing {
                        fork,
                        block_root: block.block_root(),
                        count,
                    });
                }
                Ok((block, Sidecars::None))
            }
        }
    }

    /// Gossips the block, then each sidecar on its subnet.
    /// The wall clock's time, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Broadcasts a message that passed the gossip rules on its topic, in the epoch's fork.
    ///
    /// Without a network the message stays local, which is no failure.
    pub async fn gossip(&self, kind: GossipKind, epoch: Epoch, message: Vec<u8>) {
        let Some(network) = &self.network else {
            return;
        };
        let Ok(fork_digest) = self.chain.run(move |chain| chain.fork_digest(epoch)).await else {
            return;
        };
        let topic = GossipTopic { fork_digest, kind };
        if let Err(error) = network.publish(topic.topic(), message).await {
            warn!(%error, %kind, "could not broadcast a message");
        }
    }

    async fn broadcast(
        &self,
        block: &combined::SignedBeaconBlock<P>,
        sidecars: &Sidecars<P>,
    ) -> Result<(), PublishError> {
        let Some(network) = &self.network else {
            return Ok(());
        };
        let epoch = block.slot().epoch::<P>();
        let (fork_digest, config) = self
            .chain
            .run(move |chain| (chain.fork_digest(epoch), chain.config().clone()))
            .await
            .map_err(|_| PublishError::ChainStopped)?;

        // The block goes first: peers check sidecars against a header they may already hold.
        let topic = GossipTopic {
            fork_digest,
            kind: GossipKind::BeaconBlock,
        };
        if let Err(error) = network.publish(topic.topic(), block.encode()).await {
            warn!(%error, "could not broadcast the block");
        }
        for (kind, message) in sidecars.messages(&config) {
            let topic = GossipTopic { fork_digest, kind };
            if let Err(error) = network.publish(topic.topic(), message).await {
                warn!(%error, %kind, "could not broadcast a sidecar");
            }
        }
        Ok(())
    }

    /// Imports the block, its sidecars first so it is available at once.
    async fn import(
        &self,
        block: Arc<combined::SignedBeaconBlock<P>>,
        sidecars: Sidecars<P>,
    ) -> Published {
        let payload = self.execution.verdict(&self.chain, &block).await;
        let outcome = self
            .chain
            .run(move |chain| {
                sidecars.submit(chain)?;
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

#[cfg(test)]
mod tests {
    use axiom_types::{BlobIndex, Minimal, capella};

    use super::*;

    #[test]
    fn each_fork_decodes_the_body_its_route_takes() {
        // Fixture state: a Deneb block at slot 5, alone and in its block contents.
        let mut contents = deneb::SignedBlockContents::<Minimal>::default();
        contents.signed_block.message.slot = Slot(5);
        let alone = contents.signed_block.encode();

        // Deneb takes the contents.
        assert_eq!(
            Proposal::<Minimal>::decode(&contents.encode(), ForkName::Deneb),
            Ok(Proposal::DenebBlobs(contents))
        );

        // A Deneb block alone starts with the 100-byte fixed part of a signed block.
        // The contents expect their own 12-byte fixed part of three offsets.
        assert_eq!(
            Proposal::<Minimal>::decode(&alone, ForkName::Deneb),
            Err(DecodeError::FirstOffsetMismatch {
                expected: 12,
                actual: 100,
            })
        );

        // Capella's route takes the block alone; Capella blocks hold no commitments.
        let capella =
            combined::SignedBeaconBlock::Capella(capella::SignedBeaconBlock::<Minimal>::default());
        assert_eq!(
            Proposal::<Minimal>::decode(&capella.encode(), ForkName::Capella),
            Ok(Proposal::Block(capella))
        );
    }

    #[test]
    fn blob_sidecars_spread_over_the_subnets_of_their_fork() {
        // Mainnet: Deneb spreads blobs over 6 subnets, Electra over 9.
        let config = ChainConfig::mainnet();
        let sidecar = |index| BlobSidecar::<Minimal> {
            index: BlobIndex(index),
            ..BlobSidecar::default()
        };
        let kinds = |subnets| {
            Sidecars::Blobs {
                sidecars: vec![sidecar(0), sidecar(7)],
                subnets,
            }
            .messages(&config)
            .into_iter()
            .map(|(kind, _)| kind)
            .collect::<Vec<_>>()
        };

        // Blob 7 wraps to subnet 1 in Deneb, and keeps subnet 7 in Electra.
        assert_eq!(
            kinds(BlobSubnets::deneb),
            [GossipKind::BlobSidecar(0), GossipKind::BlobSidecar(1)]
        );
        assert_eq!(
            kinds(BlobSubnets::electra),
            [GossipKind::BlobSidecar(0), GossipKind::BlobSidecar(7)]
        );
    }
}
