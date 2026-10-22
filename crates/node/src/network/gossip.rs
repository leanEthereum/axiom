//! Gossip messages: decoded in their topic's fork, validated on the chain thread, then used.

use std::{sync::Arc, time::Duration};

use axiom_beacon_json::ApiJson;
use axiom_gossip::{
    Aggregate, BlobSubnets, GossipError, GossipFork, GossipValidator, SignedAggregate,
    SlashingEvidence, SubnetVote,
};
use axiom_json::Json;
use axiom_kzg::Kzg;
use axiom_light_client::combined::{LightClientFinalityUpdate, LightClientOptimisticUpdate};
use axiom_p2p::{
    PeerId,
    eth::{GossipKind, GossipTopic},
    gossipsub::{MessageId, Topic, ValidationOutcome},
    swarm::NetworkHandle,
};
use axiom_ssz::Ssz;
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    BlobData, ForkName, Preset, Root, SubnetId,
    altair::{self, SignedContributionAndProof, SyncCommitteeMessage},
    bellatrix, capella,
    capella::SignedBlsToExecutionChange,
    combined, deneb,
    deneb::BlobSidecar,
    electra, fulu,
    gloas::{
        self, PayloadAttestationMessage, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        SignedProposerPreferences,
    },
    phase0::{self, ProposerSlashing, SignedVoluntaryExit},
};
use tokio::{sync::mpsc::UnboundedSender, time};
use tracing::{debug, warn};

use super::{
    forks::ForkDigests,
    sync::{LookupEvent, MissingBlock},
};
use crate::{
    ApiEvent, Chain, ChainError, ChainHandle, Clock, EventSender, EventTopic, ExecutionLayer,
};

/// Work on the chain that an accepted message leaves, run after it was forwarded.
type ChainJob<P> = Box<dyn FnOnce(&mut Chain<P>) -> Result<(), ChainError> + Send>;

/// What remains to do with a message once its verdict is reported.
enum Accepted<P: Preset> {
    /// A block, to be judged by the engine and imported.
    Block(Arc<combined::SignedBeaconBlock<P>>),
    /// A payload envelope, to be judged by the engine and imported.
    Envelope(Arc<SignedExecutionPayloadEnvelope<P>>),
    /// Anything else the chain consumes: votes, slashings, sidecars.
    Job(ChainJob<P>),
    /// An ignored message that needs a block the chain lacks, for a lookup to fetch.
    Lookup(MissingBlock<P>),
}

/// How an accepted message goes out on the beacon API's event stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Announce {
    /// It does not, or another step reports it with more context.
    Nothing,
    /// As the message itself.
    Plain(EventTopic),
    /// As the message wrapped with the name of its fork.
    Versioned(EventTopic, ForkName),
}

impl Announce {
    /// Publishes an accepted message, when a client listens to its topic.
    fn publish<M: ApiJson>(self, events: &EventSender, message: &M) {
        match self {
            Self::Nothing => {}
            Self::Plain(topic) => {
                if events.wants(topic) {
                    events.publish(ApiEvent::object(topic, message));
                }
            }
            Self::Versioned(topic, fork) => {
                if events.wants(topic) {
                    events.publish(ApiEvent::versioned(topic, fork, message.to_json()));
                }
            }
        }
    }
}

/// The verdict on a message and what remains to do with it.
type Checked<P> = (ValidationOutcome, Option<Accepted<P>>);

/// Handles every gossip message the network delivers.
///
/// # Overview
///
/// 1. Read the fork from the topic's digest, and decode the message as that fork's container.
/// 2. Run the gossip rules on the chain thread, giving accept, ignore, or reject.
/// 3. Report the verdict to gossipsub first, so the message propagates without delay.
/// 4. Then act on it: import a block or an envelope, count votes, or store a sidecar.
///
/// The fork is chosen once, from the digest; below that, every step is typed by the fork.
/// A message that does not decode is rejected: no honest peer sends one.
#[derive(Debug)]
pub(crate) struct GossipHandler<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The engine, for judging payloads.
    execution: Arc<ExecutionLayer>,
    /// The wall clock the timing rules read.
    clock: Arc<dyn Clock>,
    /// The network, for reporting verdicts.
    network: NetworkHandle,
    /// Message counts by topic and outcome.
    metrics: NodeMetrics,
    /// The fork each topic digest names.
    forks: Arc<ForkDigests>,
    /// Where accepted messages and missing blocks go.
    sinks: GossipSinks<P>,
}

/// Where gossip goes besides the chain: event stream clients, and lookups.
#[derive(Debug)]
pub(crate) struct GossipSinks<P: Preset> {
    /// Where accepted messages go out to event stream clients.
    pub(crate) events: EventSender,
    /// Where missing blocks go, for lookups to fetch.
    pub(crate) lookups: UnboundedSender<LookupEvent<P>>,
}

impl<P: Preset> Clone for GossipSinks<P> {
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
            lookups: self.lookups.clone(),
        }
    }
}

impl<P: Preset> Clone for GossipHandler<P> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            execution: Arc::clone(&self.execution),
            clock: Arc::clone(&self.clock),
            network: self.network.clone(),
            metrics: self.metrics.clone(),
            forks: Arc::clone(&self.forks),
            sinks: self.sinks.clone(),
        }
    }
}

impl<P: Preset> GossipHandler<P> {
    /// A handler over the node's services.
    pub(crate) fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        clock: Arc<dyn Clock>,
        network: NetworkHandle,
        metrics: NodeMetrics,
        forks: Arc<ForkDigests>,
        sinks: GossipSinks<P>,
    ) -> Self {
        Self {
            chain,
            execution,
            clock,
            network,
            metrics,
            forks,
            sinks,
        }
    }

    /// Validates one message from a peer, reports the verdict, then acts on it.
    pub(crate) async fn handle(&self, id: MessageId, topic: &Topic, data: Vec<u8>, source: PeerId) {
        let Ok(topic) = topic.as_str().parse::<GossipTopic>() else {
            // The router only delivers subscribed topics, so this cannot be an honest message.
            self.report(id, "unknown", ValidationOutcome::Reject).await;
            return;
        };
        let name = Self::topic_name(topic.kind);
        let Some(fork) = self.forks.fork_of(topic.fork_digest) else {
            // A digest outside this chain's schedule: another network, not a fault of this peer.
            self.report(id, name, ValidationOutcome::Ignore).await;
            return;
        };
        let (outcome, accepted) = self.validate(fork, topic.kind, data).await;
        self.report(id, name, outcome).await;
        if let Some(accepted) = accepted {
            self.apply(accepted, source).await;
        }
    }

    /// Validates a message as the given fork's container, dispatching once on the fork.
    async fn validate(&self, fork: ForkName, kind: GossipKind, data: Vec<u8>) -> Checked<P> {
        match fork {
            ForkName::Phase0 => self.validate_in::<phase0::BeaconState<P>>(kind, data).await,
            ForkName::Altair => self.validate_in::<altair::BeaconState<P>>(kind, data).await,
            ForkName::Bellatrix => {
                self.validate_in::<bellatrix::BeaconState<P>>(kind, data)
                    .await
            }
            ForkName::Capella => {
                self.validate_in::<capella::BeaconState<P>>(kind, data)
                    .await
            }
            ForkName::Deneb => self.validate_in::<deneb::BeaconState<P>>(kind, data).await,
            ForkName::Electra => {
                self.validate_in::<electra::BeaconState<P>>(kind, data)
                    .await
            }
            ForkName::Fulu => self.validate_in::<fulu::BeaconState<P>>(kind, data).await,
            ForkName::Gloas => self.validate_in::<gloas::BeaconState<P>>(kind, data).await,
        }
    }

    /// Validates a message on a topic of one fork.
    async fn validate_in<F>(&self, kind: GossipKind, data: Vec<u8>) -> Checked<P>
    where
        F: GossipFork<Preset = P>,
        F::SignedBeaconBlock: ApiJson + Send + 'static,
        F::SignedAggregateAndProof: ApiJson + Send + 'static,
        F::SubnetAttestation: ApiJson + Send + 'static,
        F::AttesterSlashing: ApiJson + Send + 'static,
    {
        let now = self.clock.now_ms();
        match kind {
            GossipKind::BeaconBlock => {
                self.check_or_look_up(
                    data,
                    Announce::Nothing,
                    move |validator, block: &F::SignedBeaconBlock| {
                        validator.beacon_block::<F>(block, now)
                    },
                    |block| {
                        let block = F::into_any_block(block);
                        self.announce_block(&block);
                        Some(Accepted::Block(Arc::new(block)))
                    },
                    |block, _| MissingBlock::Parent(Arc::new(F::into_any_block(block))),
                )
                .await
            }
            GossipKind::BeaconAggregateAndProof => {
                self.check_or_look_up(
                    data,
                    Announce::Nothing,
                    move |validator, aggregate: &F::SignedAggregateAndProof| {
                        validator.aggregate_and_proof::<F>(aggregate, now)
                    },
                    |aggregate| {
                        let vote = aggregate.aggregate().committee_vote();
                        Some(Self::job(move |chain| chain.on_vote(&vote)))
                    },
                    |_, root| MissingBlock::Root(root),
                )
                .await
            }
            GossipKind::BeaconAttestation(subnet) => {
                self.check_or_look_up(
                    data,
                    Announce::Plain(if F::FORK.single_attestations() {
                        EventTopic::SingleAttestation
                    } else {
                        EventTopic::Attestation
                    }),
                    move |validator, vote: &F::SubnetAttestation| {
                        validator.beacon_attestation::<F>(vote, now, SubnetId(subnet))
                    },
                    |vote| {
                        let claim = F::VOTE_INDEX.payload_claim(vote.data().index);
                        Some(Self::job(move |chain| chain.on_subnet_vote(&vote, claim)))
                    },
                    |_, root| MissingBlock::Root(root),
                )
                .await
            }
            GossipKind::AttesterSlashing => {
                self.check(
                    data,
                    Announce::Plain(EventTopic::AttesterSlashing),
                    |validator, slashing: &F::AttesterSlashing| {
                        validator.attester_slashing(slashing)
                    },
                    |slashing| {
                        let votes = slashing.conflicting_votes();
                        Some(Self::job(move |chain| chain.on_attester_slashing(&votes)))
                    },
                )
                .await
            }
            GossipKind::VoluntaryExit => {
                self.check(
                    data,
                    Announce::Plain(EventTopic::VoluntaryExit),
                    move |validator, exit: &SignedVoluntaryExit| {
                        validator.voluntary_exit::<F>(exit, now)
                    },
                    |exit| Some(Self::job(move |chain| chain.on_voluntary_exit(exit))),
                )
                .await
            }
            GossipKind::LightClientFinalityUpdate | GossipKind::LightClientOptimisticUpdate => (
                self.forward_light_client(F::FORK, kind, data, now).await,
                None,
            ),
            GossipKind::BlobSidecar(subnet) => self.validate_blob(F::FORK, subnet, data, now).await,
            GossipKind::DataColumnSidecar(subnet) => {
                self.validate_column(F::FORK.blob_data(), subnet, data, now)
                    .await
            }
            _ => self.validate_operation(F::FORK, kind, data, now).await,
        }
    }

    /// Checks a light client update against the one this node derived, and its timing.
    ///
    /// A full node forwards only the update it computed itself, once its block had time to spread.
    /// See the light client topics of the Altair light client networking spec.
    async fn forward_light_client(
        &self,
        fork: ForkName,
        kind: GossipKind,
        data: Vec<u8>,
        now: u64,
    ) -> ValidationOutcome {
        let checked = self
            .chain
            .run(move |chain| {
                let config = chain.config().clone();
                let clock = chain.store().slot_clock();
                let server = chain.light_client_mut();
                let forwarded = if kind == GossipKind::LightClientFinalityUpdate {
                    let Ok(update) = LightClientFinalityUpdate::decode(&data, fork) else {
                        return ValidationOutcome::Reject;
                    };
                    server.forward_finality_update(&update, &config, clock, now)
                } else {
                    let Ok(update) = LightClientOptimisticUpdate::decode(&data, fork) else {
                        return ValidationOutcome::Reject;
                    };
                    server.forward_optimistic_update(&update, &config, clock, now)
                };
                match forwarded {
                    Ok(()) => ValidationOutcome::Accept,
                    Err(reason) => {
                        debug!(%reason, "light client update ignored");
                        ValidationOutcome::Ignore
                    }
                }
            })
            .await;
        // The chain is shutting down; drop the message without blaming the peer.
        checked.unwrap_or(ValidationOutcome::Ignore)
    }

    /// Validates a blob sidecar, under the limits of a fork whose blobs travel as sidecars.
    async fn validate_blob(
        &self,
        fork: ForkName,
        subnet: u64,
        data: Vec<u8>,
        now: u64,
    ) -> Checked<P> {
        self.check(
            data,
            Announce::Nothing,
            move |validator, sidecar: &BlobSidecar<P>| {
                // Forks without blob sidecars have no such topic; a message there is noise.
                let limits = BlobSubnets::of(fork, validator.config())
                    .ok_or_else(|| GossipError::ignore("fork has no blob sidecars"))?;
                validator.blob_sidecar(sidecar, now, SubnetId(subnet), limits, Kzg::mainnet())
            },
            |sidecar| {
                self.announce_blob(&sidecar);
                let sidecar = Arc::new(sidecar);
                Some(Self::job(move |chain| {
                    chain.submit_blob(sidecar).map(|_| ())
                }))
            },
        )
        .await
    }

    /// Validates a data column sidecar in the column format of its fork.
    async fn validate_column(
        &self,
        blob_data: BlobData,
        subnet: u64,
        data: Vec<u8>,
        now: u64,
    ) -> Checked<P> {
        let submit = |column: combined::DataColumnSidecar<P>| {
            self.announce_column(&column);
            let column = Arc::new(column);
            Some(Self::job(move |chain| {
                chain.submit_column(column).map(|_| ())
            }))
        };
        match blob_data {
            BlobData::BlockColumns => {
                self.check(
                    data,
                    Announce::Nothing,
                    move |validator, sidecar: &fulu::DataColumnSidecar<P>| {
                        validator.data_column_sidecar(
                            sidecar,
                            now,
                            SubnetId(subnet),
                            Kzg::mainnet(),
                        )
                    },
                    |sidecar| submit(sidecar.into()),
                )
                .await
            }
            BlobData::PayloadColumns => {
                self.check(
                    data,
                    Announce::Nothing,
                    move |validator, sidecar: &gloas::DataColumnSidecar<P>| {
                        validator.gloas_data_column_sidecar(
                            sidecar,
                            now,
                            SubnetId(subnet),
                            Kzg::mainnet(),
                        )
                    },
                    |sidecar| submit(sidecar.into()),
                )
                .await
            }
            // Forks before Fulu have no column topics; a message there is noise.
            BlobData::None | BlobData::BlobSidecars => (ValidationOutcome::Ignore, None),
        }
    }

    /// Validates a message whose container no fork changed since it appeared.
    ///
    /// Without block production, the node keeps no operation pool.
    /// So the operations, bids, and preferences these topics carry are only forwarded.
    async fn validate_operation(
        &self,
        fork: ForkName,
        kind: GossipKind,
        data: Vec<u8>,
        now: u64,
    ) -> Checked<P> {
        match kind {
            GossipKind::ProposerSlashing => {
                self.check(
                    data,
                    Announce::Plain(EventTopic::ProposerSlashing),
                    |validator, slashing: &ProposerSlashing| validator.proposer_slashing(slashing),
                    |slashing| Some(Self::job(move |chain| chain.on_proposer_slashing(slashing))),
                )
                .await
            }
            GossipKind::SyncCommitteeContributionAndProof => {
                self.check(
                    data,
                    Announce::Plain(EventTopic::ContributionAndProof),
                    move |validator, contribution: &SignedContributionAndProof<P>| {
                        validator.sync_contribution(contribution, now)
                    },
                    |signed| {
                        let contribution = signed.message.contribution;
                        Some(Self::job(move |chain| chain.on_contribution(&contribution)))
                    },
                )
                .await
            }
            GossipKind::SyncCommittee(subnet) => {
                self.check(
                    data,
                    Announce::Nothing,
                    move |validator, message: &SyncCommitteeMessage| {
                        validator.sync_committee_message(message, now, SubnetId(subnet))
                    },
                    |message| Some(Self::job(move |chain| chain.on_sync_message(&message))),
                )
                .await
            }
            GossipKind::BlsToExecutionChange => {
                self.check(
                    data,
                    Announce::Plain(EventTopic::BlsToExecutionChange),
                    move |validator, change: &SignedBlsToExecutionChange| {
                        validator.bls_to_execution_change(change, now)
                    },
                    |change| Some(Self::job(move |chain| chain.on_credential_change(change))),
                )
                .await
            }
            _ => self.validate_payload_operation(fork, kind, data, now).await,
        }
    }

    /// Validates a Gloas message of the payload's own pipeline: envelopes, votes, bids, preferences.
    async fn validate_payload_operation(
        &self,
        fork: ForkName,
        kind: GossipKind,
        data: Vec<u8>,
        now: u64,
    ) -> Checked<P> {
        match kind {
            GossipKind::ExecutionPayload => {
                self.check(
                    data,
                    Announce::Nothing,
                    |validator, envelope: &SignedExecutionPayloadEnvelope<P>| {
                        validator.execution_payload_envelope(envelope)
                    },
                    |envelope| Some(Accepted::Envelope(Arc::new(envelope))),
                )
                .await
            }
            GossipKind::PayloadAttestationMessage => {
                self.check(
                    data,
                    Announce::Versioned(EventTopic::PayloadAttestationMessage, fork),
                    move |validator, message: &PayloadAttestationMessage| {
                        validator.payload_attestation_message(message, now)
                    },
                    |message| {
                        Some(Self::job(move |chain| {
                            chain.on_payload_attestation(&message)
                        }))
                    },
                )
                .await
            }
            GossipKind::ExecutionPayloadBid => {
                self.check(
                    data,
                    Announce::Versioned(EventTopic::ExecutionPayloadBid, fork),
                    move |validator, bid: &SignedExecutionPayloadBid| {
                        validator.execution_payload_bid(bid, now)
                    },
                    |bid| {
                        Some(Self::job(move |chain| {
                            chain.pool_mut().bids_mut().insert(bid);
                            Ok(())
                        }))
                    },
                )
                .await
            }
            GossipKind::ProposerPreferences => {
                self.check(
                    data,
                    Announce::Versioned(EventTopic::ProposerPreferences, fork),
                    move |validator, preferences: &SignedProposerPreferences| {
                        validator.proposer_preferences(preferences, now)
                    },
                    |_| None,
                )
                .await
            }
            // Every other topic has its own validation above.
            _ => (ValidationOutcome::Ignore, None),
        }
    }

    /// Wraps work on the chain as what an accepted message leaves to do.
    fn job(
        job: impl FnOnce(&mut Chain<P>) -> Result<(), ChainError> + Send + 'static,
    ) -> Accepted<P> {
        Accepted::Job(Box::new(job))
    }

    /// Decodes a message and runs one gossip rule on the chain thread.
    ///
    /// # Arguments
    ///
    /// - `data`: the decompressed SSZ payload.
    /// - `announce`: the event stream topic an accepted message goes out on, if any.
    /// - `rule`: the gossip rule for the message's topic.
    /// - `then`: what to keep of an accepted message, if anything.
    async fn check<M, R, T>(
        &self,
        data: Vec<u8>,
        announce: Announce,
        rule: R,
        then: T,
    ) -> Checked<P>
    where
        M: Ssz + ApiJson + Send + 'static,
        R: FnOnce(&mut GossipValidator<'_, '_, P>, &M) -> Result<(), GossipError> + Send + 'static,
        T: FnOnce(M) -> Option<Accepted<P>>,
    {
        self.check_or_look_up(data, announce, rule, then, |_, root| {
            MissingBlock::Root(root)
        })
        .await
    }

    /// Runs a gossip rule as the plain check does, and names a block the chain lacks.
    ///
    /// A message ignored for want of a block is kept for a lookup, as the p2p spec allows.
    ///
    /// # Arguments
    ///
    /// - `missing`: what a lookup fetches for an ignored message and the root it lacks.
    async fn check_or_look_up<M, R, T, L>(
        &self,
        data: Vec<u8>,
        announce: Announce,
        rule: R,
        then: T,
        missing: L,
    ) -> Checked<P>
    where
        M: Ssz + ApiJson + Send + 'static,
        R: FnOnce(&mut GossipValidator<'_, '_, P>, &M) -> Result<(), GossipError> + Send + 'static,
        T: FnOnce(M) -> Option<Accepted<P>>,
        L: FnOnce(M, Root) -> MissingBlock<P>,
    {
        let Ok(message) = M::decode(&data) else {
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
            Ok((Ok(()), message)) => {
                announce.publish(&self.sinks.events, &message);
                (ValidationOutcome::Accept, then(message))
            }
            Ok((Err(error @ GossipError::Ignore { .. }), message)) => {
                debug!(%error, "gossip ignored");
                let lookup = error
                    .unseen_block()
                    .map(|root| Accepted::Lookup(missing(message, root)));
                (ValidationOutcome::Ignore, lookup)
            }
            Ok((Err(error @ GossipError::Reject { .. }), _)) => {
                debug!(%error, "gossip rejected");
                (ValidationOutcome::Reject, None)
            }
            // The chain is shutting down; drop the message without blaming the peer.
            Err(_) => (ValidationOutcome::Ignore, None),
        }
    }

    /// Acts on a message after its verdict, forwarded or kept for a lookup.
    async fn apply(&self, accepted: Accepted<P>, source: PeerId) {
        let outcome = match accepted {
            Accepted::Block(block) => {
                let payload = self.execution.verdict(&self.chain, &block).await;
                // Gossip admits a block up to the clock disparity early; it waits for its slot.
                let slot = block.slot();
                if let Ok(start) = self.chain.run(move |chain| chain.slot_start_ms(slot)).await {
                    let early = start.saturating_sub(self.clock.now_ms());
                    time::sleep(Duration::from_millis(early)).await;
                }
                let now = self.clock.now_ms();
                self.chain
                    .run(move |chain| {
                        // The store's clock may lag the ticker, so bring it to now first.
                        chain.on_tick(now)?;
                        chain.submit_block(block, payload).map(|_| ())
                    })
                    .await
            }
            Accepted::Envelope(envelope) => {
                self.announce_envelope(&envelope).await;
                let payload = self.execution.judge_envelope(&self.chain, &envelope).await;
                self.chain
                    .run(move |chain| chain.submit_envelope(envelope, payload).map(|_| ()))
                    .await
            }
            Accepted::Job(job) => self.chain.run(job).await,
            Accepted::Lookup(missing) => {
                // A stopped network loop has no lookups to start.
                let _stopped = self.sinks.lookups.send(LookupEvent::Missing {
                    peer: source,
                    missing,
                });
                return;
            }
        };
        match outcome {
            Ok(Ok(())) | Err(_) => {}
            // Gossip rules passed but the fork choice refused: log, the peer was not at fault.
            Ok(Err(error)) => warn!(%error, "accepted gossip not applied"),
        }
    }

    /// Tells event stream clients of a block that passed gossip validation.
    fn announce_block(&self, block: &combined::SignedBeaconBlock<P>) {
        if self.sinks.events.wants(EventTopic::BlockGossip) {
            self.sinks.events.publish(ApiEvent::json(
                EventTopic::BlockGossip,
                Json::from([
                    ("slot", Json::from(block.slot().0.to_string())),
                    ("block", Json::from(block.block_root().to_string())),
                ]),
            ));
        }
    }

    /// Tells event stream clients of a blob sidecar that passed gossip validation.
    fn announce_blob(&self, sidecar: &BlobSidecar<P>) {
        if self.sinks.events.wants(EventTopic::BlobSidecar) {
            let header = &sidecar.signed_block_header.message;
            self.sinks.events.publish(ApiEvent::json(
                EventTopic::BlobSidecar,
                Json::from([
                    (
                        "block_root",
                        Json::from(header.hash_tree_root().to_string()),
                    ),
                    ("index", Json::from(sidecar.index.0.to_string())),
                    ("slot", Json::from(header.slot.0.to_string())),
                    (
                        "kzg_commitment",
                        Json::from(sidecar.kzg_commitment.to_string()),
                    ),
                    (
                        "versioned_hash",
                        Json::from(sidecar.kzg_commitment.versioned_hash().to_string()),
                    ),
                ]),
            ));
        }
    }

    /// Tells event stream clients of a data column sidecar that passed gossip validation.
    fn announce_column(&self, column: &combined::DataColumnSidecar<P>) {
        if self.sinks.events.wants(EventTopic::DataColumnSidecar) {
            self.sinks.events.publish(ApiEvent::json(
                EventTopic::DataColumnSidecar,
                Json::from([
                    ("block_root", Json::from(column.block_root().to_string())),
                    ("index", Json::from(column.index().0.to_string())),
                    ("slot", Json::from(column.slot().0.to_string())),
                ]),
            ));
        }
    }

    /// Tells event stream clients of a payload envelope that passed gossip validation.
    ///
    /// The envelope names its block, whose slot the chain knows.
    async fn announce_envelope(&self, envelope: &SignedExecutionPayloadEnvelope<P>) {
        if !self.sinks.events.wants(EventTopic::ExecutionPayloadGossip) {
            return;
        }
        let message = &envelope.message;
        let root = message.beacon_block_root;
        let Ok(Ok(Some(slot))) = self.chain.run(move |chain| chain.block_slot(root)).await else {
            return;
        };
        self.sinks.events.publish(ApiEvent::json(
            EventTopic::ExecutionPayloadGossip,
            Json::from([
                ("slot", Json::from(slot.0.to_string())),
                (
                    "builder_index",
                    Json::from(message.builder_index.0.to_string()),
                ),
                (
                    "block_hash",
                    Json::from(message.payload.block_hash.to_string()),
                ),
                ("block_root", Json::from(root.to_string())),
            ]),
        ));
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
            GossipKind::ExecutionPayload => "execution_payload",
            GossipKind::PayloadAttestationMessage => "payload_attestation_message",
            GossipKind::ExecutionPayloadBid => "execution_payload_bid",
            GossipKind::ProposerPreferences => "proposer_preferences",
        }
    }
}
