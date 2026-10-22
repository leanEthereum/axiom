//! Gossip messages: decoded, validated on the chain thread, reported, then used.

use std::sync::Arc;

use axiom_gossip::{GossipError, GossipValidator};
use axiom_kzg::Kzg;
use axiom_p2p::{
    eth::{GossipKind, GossipTopic},
    gossipsub::{MessageId, Topic, ValidationOutcome},
    swarm::NetworkHandle,
};
use axiom_ssz::Ssz;
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    AttesterSlashing, DataColumnSidecar, Preset, ProposerSlashing, SignedAggregateAndProof,
    SignedBeaconBlock, SignedBlsToExecutionChange, SignedContributionAndProof, SignedVoluntaryExit,
    SingleAttestation, SubnetId, SyncCommitteeMessage,
};
use tracing::{debug, warn};

use crate::{Chain, ChainHandle, Clock, ExecutionLayer};

/// A message that passed validation and still has work to do once forwarded.
#[derive(Debug)]
enum Accepted<P: Preset> {
    /// A block, to be judged by the engine and imported.
    Block(Arc<SignedBeaconBlock<P>>),
    /// An aggregate, whose votes feed the fork choice.
    Aggregate(Box<SignedAggregateAndProof<P>>),
    /// Equivocation evidence, which removes weight from the fork choice.
    AttesterSlashing(Box<AttesterSlashing<P>>),
    /// A custody column, which may complete a waiting block.
    Column(Arc<DataColumnSidecar<P>>),
}

/// Handles every gossip message the network delivers.
///
/// # Overview
///
/// ```text
///     bytes ──decode──> message ──chain thread: gossip rules──> accept | ignore | reject
///                                                                  │
///                     report to gossipsub first, so the message propagates without delay
///                                                                  │
///                                    then: import a block, count votes, store a column
/// ```
///
/// A message that does not decode is rejected: no honest peer sends one.
#[derive(Debug)]
pub(crate) struct GossipHandler<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for judging block payloads.
    execution: Arc<ExecutionLayer>,
    /// The wall clock the timing rules read.
    clock: Arc<dyn Clock>,
    /// The network, for reporting verdicts.
    network: NetworkHandle,
    /// Message counts by topic and outcome.
    metrics: NodeMetrics,
}

impl<P: Preset> Clone for GossipHandler<P> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            execution: Arc::clone(&self.execution),
            clock: Arc::clone(&self.clock),
            network: self.network.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<P: Preset> GossipHandler<P> {
    /// A handler over the node's services.
    pub(crate) const fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        clock: Arc<dyn Clock>,
        network: NetworkHandle,
        metrics: NodeMetrics,
    ) -> Self {
        Self {
            chain,
            execution,
            clock,
            network,
            metrics,
        }
    }

    /// Validates one message, reports the verdict, then acts on it.
    pub(crate) async fn handle(&self, id: MessageId, topic: &Topic, data: Vec<u8>) {
        let Ok(topic) = topic.as_str().parse::<GossipTopic>() else {
            // The router only delivers subscribed topics, so this cannot be an honest message.
            self.report(id, "unknown", ValidationOutcome::Reject).await;
            return;
        };
        let name = Self::topic_name(topic.kind);
        let (outcome, accepted) = self.validate(topic.kind, &data).await;
        self.report(id, name, outcome).await;
        if let Some(accepted) = accepted {
            self.apply(accepted).await;
        }
    }

    /// Decodes and validates a message, returning the verdict and what remains to do.
    async fn validate(
        &self,
        kind: GossipKind,
        data: &[u8],
    ) -> (ValidationOutcome, Option<Accepted<P>>) {
        let now = self.clock.now_ms();
        match kind {
            GossipKind::BeaconBlock
            | GossipKind::BeaconAggregateAndProof
            | GossipKind::BeaconAttestation(_)
            | GossipKind::AttesterSlashing
            | GossipKind::DataColumnSidecar(_) => self.validate_chain_input(kind, data, now).await,
            _ => (self.validate_operation(kind, data, now).await, None),
        }
    }

    /// Validates a message the chain consumes: blocks, votes, slashing evidence, columns.
    async fn validate_chain_input(
        &self,
        kind: GossipKind,
        data: &[u8],
        now: u64,
    ) -> (ValidationOutcome, Option<Accepted<P>>) {
        match kind {
            GossipKind::BeaconBlock => {
                self.check(
                    data,
                    move |validator, block: &SignedBeaconBlock<P>| {
                        validator.beacon_block(block, now)
                    },
                    |block| Some(Accepted::Block(Arc::new(block))),
                )
                .await
            }
            GossipKind::BeaconAggregateAndProof => {
                self.check(
                    data,
                    move |validator, aggregate: &SignedAggregateAndProof<P>| {
                        validator.aggregate_and_proof(aggregate, now)
                    },
                    |aggregate| Some(Accepted::Aggregate(Box::new(aggregate))),
                )
                .await
            }
            GossipKind::BeaconAttestation(subnet) => {
                // Single votes are forwarded; the fork choice counts them once aggregated.
                self.check(
                    data,
                    move |validator, attestation: &SingleAttestation| {
                        validator.beacon_attestation(attestation, now, SubnetId(subnet))
                    },
                    |_| None,
                )
                .await
            }
            GossipKind::AttesterSlashing => {
                self.check(
                    data,
                    |validator, slashing: &AttesterSlashing<P>| {
                        validator.attester_slashing(slashing)
                    },
                    |slashing| Some(Accepted::AttesterSlashing(Box::new(slashing))),
                )
                .await
            }
            GossipKind::DataColumnSidecar(subnet) => {
                self.check(
                    data,
                    move |validator, sidecar: &DataColumnSidecar<P>| {
                        validator.data_column_sidecar(
                            sidecar,
                            now,
                            SubnetId(subnet),
                            Kzg::mainnet(),
                        )
                    },
                    |sidecar| Some(Accepted::Column(Arc::new(sidecar))),
                )
                .await
            }
            _ => (ValidationOutcome::Ignore, None),
        }
    }

    /// Validates a message the node only forwards: exits, slashings, sync messages, changes.
    ///
    /// Without block production, the node keeps no operation pool, so nothing follows acceptance.
    async fn validate_operation(
        &self,
        kind: GossipKind,
        data: &[u8],
        now: u64,
    ) -> ValidationOutcome {
        let (outcome, _) = match kind {
            GossipKind::VoluntaryExit => {
                self.check(
                    data,
                    move |validator, exit: &SignedVoluntaryExit| {
                        validator.voluntary_exit(exit, now)
                    },
                    |_| None,
                )
                .await
            }
            GossipKind::ProposerSlashing => {
                self.check(
                    data,
                    |validator, slashing: &ProposerSlashing| validator.proposer_slashing(slashing),
                    |_| None,
                )
                .await
            }
            GossipKind::SyncCommitteeContributionAndProof => {
                self.check(
                    data,
                    move |validator, contribution: &SignedContributionAndProof<P>| {
                        validator.sync_contribution(contribution, now)
                    },
                    |_| None,
                )
                .await
            }
            GossipKind::SyncCommittee(subnet) => {
                self.check(
                    data,
                    move |validator, message: &SyncCommitteeMessage| {
                        validator.sync_committee_message(message, now, SubnetId(subnet))
                    },
                    |_| None,
                )
                .await
            }
            GossipKind::BlsToExecutionChange => {
                self.check(
                    data,
                    move |validator, change: &SignedBlsToExecutionChange| {
                        validator.bls_to_execution_change(change, now)
                    },
                    |_| None,
                )
                .await
            }
            // Topics of earlier forks or of light clients, which this node never joins.
            // Chain inputs never reach here: they have their own validation.
            _ => (ValidationOutcome::Ignore, None),
        };
        outcome
    }

    /// Decodes a message and runs one gossip rule on the chain thread.
    ///
    /// # Arguments
    ///
    /// - `data`: the decompressed SSZ payload.
    /// - `rule`: the gossip rule for the message's topic.
    /// - `then`: what to keep of an accepted message, if anything.
    async fn check<M, R, T>(
        &self,
        data: &[u8],
        rule: R,
        then: T,
    ) -> (ValidationOutcome, Option<Accepted<P>>)
    where
        M: Ssz + Send + 'static,
        R: FnOnce(&mut GossipValidator<'_, '_, P>, &M) -> Result<(), GossipError> + Send + 'static,
        T: FnOnce(M) -> Option<Accepted<P>>,
    {
        let Ok(message) = M::decode(data) else {
            return (ValidationOutcome::Reject, None);
        };
        let checked = self
            .chain
            .run(move |chain: &mut Chain<P>| {
                let verdict = chain.validate_gossip(|validator| rule(validator, &message));
                (verdict, message)
            })
            .await;
        match checked {
            Ok((Ok(()), message)) => (ValidationOutcome::Accept, then(message)),
            Ok((Err(GossipError::Ignore(reason)), _)) => {
                debug!(reason, "gossip ignored");
                (ValidationOutcome::Ignore, None)
            }
            Ok((Err(GossipError::Reject(reason)), _)) => {
                debug!(reason, "gossip rejected");
                (ValidationOutcome::Reject, None)
            }
            // The chain is shutting down; drop the message without blaming the peer.
            Err(_) => (ValidationOutcome::Ignore, None),
        }
    }

    /// Acts on an accepted message, after it was forwarded.
    async fn apply(&self, accepted: Accepted<P>) {
        let outcome = match accepted {
            Accepted::Block(block) => {
                let payload = self.execution.verdict(&block.message).await;
                self.chain
                    .run(move |chain| chain.submit_block(block, payload).map(|_| ()))
                    .await
            }
            Accepted::Aggregate(aggregate) => {
                self.chain
                    .run(move |chain| chain.on_attestation(&aggregate.message.aggregate))
                    .await
            }
            Accepted::AttesterSlashing(slashing) => {
                self.chain
                    .run(move |chain| chain.on_attester_slashing(&slashing))
                    .await
            }
            Accepted::Column(column) => {
                self.chain
                    .run(move |chain| chain.submit_column(column).map(|_| ()))
                    .await
            }
        };
        match outcome {
            Ok(Ok(())) | Err(_) => {}
            // Gossip rules passed but the fork choice refused: log, the peer was not at fault.
            Ok(Err(error)) => warn!(%error, "accepted gossip not applied"),
        }
    }

    /// Sends a verdict to the router and counts it.
    async fn report(&self, id: MessageId, topic: &str, outcome: ValidationOutcome) {
        let label = match outcome {
            ValidationOutcome::Accept => "accept",
            ValidationOutcome::Ignore => "ignore",
            ValidationOutcome::Reject => "reject",
        };
        self.metrics
            .gossip_messages
            .with_label_values([topic, label])
            .inc();
        // A stopped network has nobody to tell.
        let _stopped = self.network.report_validation(id, outcome).await;
    }

    /// A short topic name for metrics, without the fork digest or subnet.
    const fn topic_name(kind: GossipKind) -> &'static str {
        match kind {
            GossipKind::BeaconBlock => "beacon_block",
            GossipKind::BeaconAggregateAndProof => "beacon_aggregate_and_proof",
            GossipKind::BeaconAttestation(_) => "beacon_attestation",
            GossipKind::VoluntaryExit => "voluntary_exit",
            GossipKind::ProposerSlashing => "proposer_slashing",
            GossipKind::AttesterSlashing => "attester_slashing",
            GossipKind::SyncCommitteeContributionAndProof => {
                "sync_committee_contribution_and_proof"
            }
            GossipKind::SyncCommittee(_) => "sync_committee",
            GossipKind::BlsToExecutionChange => "bls_to_execution_change",
            GossipKind::LightClientFinalityUpdate => "light_client_finality_update",
            GossipKind::LightClientOptimisticUpdate => "light_client_optimistic_update",
            GossipKind::BlobSidecar(_) => "blob_sidecar",
            GossipKind::DataColumnSidecar(_) => "data_column_sidecar",
        }
    }
}
