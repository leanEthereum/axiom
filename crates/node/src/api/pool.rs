//! The operation pool routes: submissions from validators, and the pool's contents.
//!
//! A submission passes the same gossip rules as a network message, then joins the pool.
//! It is broadcast only when it passes, so a bad one costs the node no reputation.
//!
//! Slashings and exits come one per request, and a refusal is a plain error.
//! Every other operation comes as a list, each item handled alone.
//! A list's refusals are reported item by item, while the accepted items stand.
//! See the pool and aggregate routes of beacon-APIs.

use axiom_beacon_json::ApiJson;
use axiom_gossip::{
    Aggregate, GossipError, GossipFork, SignedAggregate, SlashingEvidence, SubnetVote,
};
use axiom_http::{Request, Response, StatusCode};
use axiom_json::Json;
use axiom_operation_pool::{PackedAttestation, PoolError, PoolFork, SyncPool};
use axiom_p2p::eth::GossipKind;
use axiom_ssz::Ssz;
use axiom_types::{
    CommitteeIndex, ForkName, Preset, Slot, SubnetId,
    altair::{self, SignedContributionAndProof, SyncCommitteeMessage},
    bellatrix,
    capella::{self, SignedBlsToExecutionChange},
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
    deneb, electra, fulu,
    gloas::{self, PayloadAttestationMessage},
    hstar,
    phase0::{self, ProposerSlashing, SignedVoluntaryExit},
    vote::ConflictingVotes,
};
use tracing::debug;

use super::{
    ApiContext,
    query::{Body, Query},
    reply::{ApiError, ApiResult, Failure, Reply, Routes},
};
use crate::{
    Chain,
    monitor::{Observed, Source},
};

/// What an accepted submission does on the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spread {
    /// The submission is news, so it goes out on its topic.
    Broadcast,
    /// The node already holds everything the submission carries, so peers would drop it.
    Known,
}

impl Spread {
    /// The fate of an aggregate, or a sync contribution, after its gossip rules.
    ///
    /// Aggregators of one committee often hold the same votes, and each submits them.
    /// Gossip ignores a repeat whose votes are already seen, so the first one alone spreads.
    /// The repeat is still valid, so the client is told it was accepted.
    /// Only a rejection, such as a bad signature, is refused.
    fn of_aggregate(verdict: Result<(), GossipError>) -> Result<Self, ApiError> {
        match verdict {
            Ok(()) => Ok(Self::Broadcast),
            Err(error @ GossipError::Ignore { .. }) => {
                debug!(%error, "aggregate adds nothing the node has not seen");
                Ok(Self::Known)
            }
            Err(error @ GossipError::Reject { .. }) => Err(PoolRoutes::refusal(error)),
        }
    }
}

/// Routes under `/eth/v1/beacon/pool`, `/eth/v2/beacon/pool`, and the signed aggregate routes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PoolRoutes;

impl PoolRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .post("/eth/v2/beacon/pool/attestations", Self::attestations::<P>)
            .get(
                "/eth/v2/beacon/pool/attestations",
                Self::pooled_attestations::<P>,
            )
            .post(
                "/eth/v2/validator/aggregate_and_proofs",
                Self::aggregates::<P>,
            )
            .post(
                "/eth/v2/beacon/pool/attester_slashings",
                Self::attester_slashings::<P>,
            )
            .get(
                "/eth/v2/beacon/pool/attester_slashings",
                Self::pooled_attester_slashings::<P>,
            )
            .post(
                "/eth/v1/beacon/pool/proposer_slashings",
                Self::proposer_slashings::<P>,
            )
            .get(
                "/eth/v1/beacon/pool/proposer_slashings",
                Self::pooled_proposer_slashings::<P>,
            )
            .post(
                "/eth/v1/beacon/pool/voluntary_exits",
                Self::voluntary_exits::<P>,
            )
            .get(
                "/eth/v1/beacon/pool/voluntary_exits",
                Self::pooled_exits::<P>,
            )
            .post(
                "/eth/v1/beacon/pool/bls_to_execution_changes",
                Self::credential_changes::<P>,
            )
            .get(
                "/eth/v1/beacon/pool/bls_to_execution_changes",
                Self::pooled_changes::<P>,
            )
            .post(
                "/eth/v1/beacon/pool/sync_committees",
                Self::sync_messages::<P>,
            )
            .post(
                "/eth/v1/validator/contribution_and_proofs",
                Self::contributions::<P>,
            )
            .post(
                "/eth/v1/beacon/pool/payload_attestations",
                Self::payload_attestations::<P>,
            )
    }

    /// Single votes: subnet attestations of the fork the version header names.
    async fn attestations<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let fork = Self::fork(&context, &request).await?;
        match fork {
            ForkName::Phase0 => Self::votes_in::<phase0::BeaconState<P>>(context, request).await,
            ForkName::Altair => Self::votes_in::<altair::BeaconState<P>>(context, request).await,
            ForkName::Bellatrix => {
                Self::votes_in::<bellatrix::BeaconState<P>>(context, request).await
            }
            ForkName::Capella => Self::votes_in::<capella::BeaconState<P>>(context, request).await,
            ForkName::Deneb => Self::votes_in::<deneb::BeaconState<P>>(context, request).await,
            ForkName::Electra => Self::votes_in::<electra::BeaconState<P>>(context, request).await,
            ForkName::Fulu => Self::votes_in::<fulu::BeaconState<P>>(context, request).await,
            ForkName::Gloas => Self::votes_in::<gloas::BeaconState<P>>(context, request).await,
            ForkName::Hstar => Self::votes_in::<hstar::BeaconState<P>>(context, request).await,
        }
    }

    /// Signed aggregates of the fork the version header names.
    async fn aggregates<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let fork = Self::fork(&context, &request).await?;
        match fork {
            ForkName::Phase0 => {
                Self::aggregates_in::<phase0::BeaconState<P>>(context, request).await
            }
            ForkName::Altair => {
                Self::aggregates_in::<altair::BeaconState<P>>(context, request).await
            }
            ForkName::Bellatrix => {
                Self::aggregates_in::<bellatrix::BeaconState<P>>(context, request).await
            }
            ForkName::Capella => {
                Self::aggregates_in::<capella::BeaconState<P>>(context, request).await
            }
            ForkName::Deneb => Self::aggregates_in::<deneb::BeaconState<P>>(context, request).await,
            ForkName::Electra => {
                Self::aggregates_in::<electra::BeaconState<P>>(context, request).await
            }
            ForkName::Fulu => Self::aggregates_in::<fulu::BeaconState<P>>(context, request).await,
            ForkName::Gloas => Self::aggregates_in::<gloas::BeaconState<P>>(context, request).await,
            ForkName::Hstar => Self::aggregates_in::<hstar::BeaconState<P>>(context, request).await,
        }
    }

    /// Attester slashings of the fork the version header names.
    async fn attester_slashings<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let fork = Self::fork(&context, &request).await?;
        match fork {
            ForkName::Phase0 => {
                Self::slashings_in::<phase0::BeaconState<P>>(context, request).await
            }
            ForkName::Altair => {
                Self::slashings_in::<altair::BeaconState<P>>(context, request).await
            }
            ForkName::Bellatrix => {
                Self::slashings_in::<bellatrix::BeaconState<P>>(context, request).await
            }
            ForkName::Capella => {
                Self::slashings_in::<capella::BeaconState<P>>(context, request).await
            }
            ForkName::Deneb => Self::slashings_in::<deneb::BeaconState<P>>(context, request).await,
            ForkName::Electra => {
                Self::slashings_in::<electra::BeaconState<P>>(context, request).await
            }
            ForkName::Fulu => Self::slashings_in::<fulu::BeaconState<P>>(context, request).await,
            ForkName::Gloas => Self::slashings_in::<gloas::BeaconState<P>>(context, request).await,
            ForkName::Hstar => Self::slashings_in::<hstar::BeaconState<P>>(context, request).await,
        }
    }

    /// Single votes of one fork: checked, counted, pooled, and broadcast on their subnet.
    async fn votes_in<F>(context: ApiContext<F::Preset>, request: Request) -> ApiResult
    where
        F: GossipFork,
        F::SubnetAttestation: ApiJson + Send + 'static,
    {
        let votes: Vec<F::SubnetAttestation> = Body(&request).items()?;
        let now = context.publisher.now_ms();
        let mut failures = Vec::<Failure>::new();
        for (position, vote) in votes.into_iter().enumerate() {
            let data = vote.data().clone();
            let committee = vote.committee_index();
            let bytes = vote.encode();
            let outcome = context
                .query(move |chain| {
                    let per_slot = chain
                        .head_state()?
                        .clone()
                        .committees(data.target.epoch)
                        .map_err(|error| ApiError::bad_request(error.to_string()))?
                        .committees_per_slot();
                    let config = chain.config();
                    // See `compute_subnet_for_attestation` in the phase0 validator spec.
                    let since_epoch = per_slot * (data.slot.0 % F::Preset::SLOTS_PER_EPOCH);
                    let subnet = (since_epoch + committee.0) % config.attestation_subnet_count;
                    chain
                        .validate_gossip(|validator| {
                            validator.beacon_attestation::<F>(&vote, now, SubnetId(subnet))
                        })
                        .map_err(Self::refusal)?;
                    let claim = F::VOTE_INDEX.payload_claim(vote.data().index);
                    // A vote of the current slot counts in fork choice only from the next slot.
                    // It is pooled and broadcast all the same; the store sees it again in a block.
                    match chain.on_subnet_vote(&vote, claim) {
                        Ok(attester) => {
                            let data = vote.data();
                            chain.observe(Observed::Single { attester, data }, Source::Api, now);
                        }
                        Err(error) => debug!(%error, "vote pooled but not counted yet"),
                    }
                    Ok(subnet)
                })
                .await;
            match outcome {
                Ok(subnet) => {
                    let epoch = data.slot.epoch::<F::Preset>();
                    context
                        .publisher
                        .gossip(GossipKind::BeaconAttestation(subnet), epoch, bytes)
                        .await;
                }
                Err(error) => failures.push((position, error.to_string())),
            }
        }
        Reply::submission(failures)
    }

    /// Signed aggregates of one fork: checked, counted, pooled, and broadcast.
    async fn aggregates_in<F>(context: ApiContext<F::Preset>, request: Request) -> ApiResult
    where
        F: GossipFork,
        F::SignedAggregateAndProof: ApiJson + Send + 'static,
    {
        let aggregates: Vec<F::SignedAggregateAndProof> = Body(&request).items()?;
        let now = context.publisher.now_ms();
        let mut failures = Vec::<Failure>::new();
        for (position, signed) in aggregates.into_iter().enumerate() {
            let epoch = signed.aggregate().data().slot.epoch::<F::Preset>();
            let bytes = signed.encode();
            let outcome = context
                .query(move |chain| {
                    let verdict = chain.validate_gossip(|validator| {
                        validator.aggregate_and_proof::<F>(&signed, now)
                    });
                    if Spread::of_aggregate(verdict)? == Spread::Known {
                        return Ok(Spread::Known);
                    }
                    let vote = signed.aggregate().committee_vote();
                    let aggregator = signed.aggregator_index();
                    let observed = Observed::Aggregate {
                        aggregator,
                        vote: &vote,
                    };
                    chain.observe(observed, Source::Api, now);
                    if let Err(error) = chain.on_vote(&vote) {
                        debug!(%error, "aggregate pooled but not counted yet");
                    }
                    Ok(Spread::Broadcast)
                })
                .await;
            match outcome {
                Ok(Spread::Broadcast) => {
                    context
                        .publisher
                        .gossip(GossipKind::BeaconAggregateAndProof, epoch, bytes)
                        .await;
                }
                Ok(Spread::Known) => {}
                Err(error) => failures.push((position, error.to_string())),
            }
        }
        Reply::submission(failures)
    }

    /// An attester slashing of one fork: checked, pooled, and broadcast.
    async fn slashings_in<F>(context: ApiContext<F::Preset>, request: Request) -> ApiResult
    where
        F: GossipFork,
        F::AttesterSlashing: ApiJson + Send + 'static,
    {
        let slashing: F::AttesterSlashing = Body(&request).json_item()?;
        let bytes = slashing.encode();
        let epoch = context
            .query(move |chain| {
                chain
                    .validate_gossip(|validator| validator.attester_slashing(&slashing))
                    .map_err(Self::refusal)?;
                let votes = slashing.conflicting_votes();
                chain.observe(Observed::AttesterSlashing(&votes), Source::Api, 0);
                chain.on_attester_slashing(&votes)?;
                Ok(chain.store().current_epoch())
            })
            .await?;
        context
            .publisher
            .gossip(GossipKind::AttesterSlashing, epoch, bytes)
            .await;
        Ok(Response::new(StatusCode::OK))
    }

    /// A proposer slashing: checked, pooled, and broadcast.
    async fn proposer_slashings<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let slashing: ProposerSlashing = Body(&request).json_item()?;
        Self::offer(
            &context,
            slashing,
            GossipKind::ProposerSlashing,
            |chain, slashing, _| {
                chain
                    .validate_gossip(|validator| validator.proposer_slashing(&slashing))
                    .map_err(Self::refusal)?;
                chain.observe(Observed::ProposerSlashing(&slashing), Source::Api, 0);
                chain.on_proposer_slashing(slashing)?;
                Ok(Spread::Broadcast)
            },
        )
        .await
    }

    /// A voluntary exit: checked under the clock's fork, pooled, and broadcast.
    async fn voluntary_exits<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let exit: SignedVoluntaryExit = Body(&request).json_item()?;
        Self::offer(
            &context,
            exit,
            GossipKind::VoluntaryExit,
            |chain, exit, now| {
                let fork = chain.config().fork_at(chain.store().current_epoch());
                let verdict = match fork {
                    ForkName::Phase0 => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<phase0::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Altair => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<altair::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Bellatrix => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<bellatrix::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Capella => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<capella::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Deneb => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<deneb::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Electra => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<electra::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Fulu => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<fulu::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Gloas => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<gloas::BeaconState<P>>(&exit, now)
                    }),
                    ForkName::Hstar => chain.validate_gossip(|validator| {
                        validator.voluntary_exit::<hstar::BeaconState<P>>(&exit, now)
                    }),
                };
                verdict.map_err(Self::refusal)?;
                chain.observe(Observed::Exit(&exit.message), Source::Api, now);
                chain.on_voluntary_exit(exit)?;
                Ok(Spread::Broadcast)
            },
        )
        .await
    }

    /// Withdrawal credential changes: checked, pooled, and broadcast.
    async fn credential_changes<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let changes: Vec<SignedBlsToExecutionChange> = Body(&request).json_items()?;
        Self::submit(
            &context,
            changes,
            GossipKind::BlsToExecutionChange,
            |chain, change, now| {
                chain
                    .validate_gossip(|validator| validator.bls_to_execution_change(&change, now))
                    .map_err(Self::refusal)?;
                chain.on_credential_change(change)?;
                Ok(Spread::Broadcast)
            },
        )
        .await
    }

    /// Sync committee messages: checked on each subnet of the member's seats, pooled, broadcast.
    async fn sync_messages<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let messages: Vec<SyncCommitteeMessage> = Body(&request).json_items()?;
        let now = context.publisher.now_ms();
        let mut failures = Vec::<Failure>::new();
        for (position, message) in messages.into_iter().enumerate() {
            let bytes = message.encode();
            let epoch = message.slot.epoch::<P>();
            let outcome = context
                .query(move |chain| {
                    let subnets = Self::sync_subnets(chain, &message)?;
                    for subnet in &subnets {
                        chain
                            .validate_gossip(|validator| {
                                validator.sync_committee_message(&message, now, SubnetId(*subnet))
                            })
                            .map_err(Self::refusal)?;
                    }
                    chain.observe(Observed::SyncMessage(&message), Source::Api, now);
                    chain.on_sync_message(&message)?;
                    Ok(subnets)
                })
                .await;
            match outcome {
                Ok(subnets) => {
                    for subnet in subnets {
                        context
                            .publisher
                            .gossip(GossipKind::SyncCommittee(subnet), epoch, bytes.clone())
                            .await;
                    }
                }
                Err(error) => failures.push((position, error.to_string())),
            }
        }
        Reply::submission(failures)
    }

    /// Signed sync contributions: checked, pooled, and broadcast.
    async fn contributions<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let contributions: Vec<SignedContributionAndProof<P>> = Body(&request).json_items()?;
        Self::submit(
            &context,
            contributions,
            GossipKind::SyncCommitteeContributionAndProof,
            |chain, signed, now| {
                let verdict =
                    chain.validate_gossip(|validator| validator.sync_contribution(&signed, now));
                if Spread::of_aggregate(verdict)? == Spread::Known {
                    return Ok(Spread::Known);
                }
                let observed = Observed::Contribution {
                    aggregator: signed.message.aggregator_index,
                    contribution: &signed.message.contribution,
                };
                chain.observe(observed, Source::Api, now);
                chain.on_contribution(&signed.message.contribution)?;
                Ok(Spread::Broadcast)
            },
        )
        .await
    }

    /// Payload timeliness votes, as JSON or SSZ: checked, counted, pooled, and broadcast.
    async fn payload_attestations<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let messages: Vec<PayloadAttestationMessage> = Body(&request).items()?;
        Self::submit(
            &context,
            messages,
            GossipKind::PayloadAttestationMessage,
            |chain, message, now| {
                chain
                    .validate_gossip(|validator| {
                        validator.payload_attestation_message(&message, now)
                    })
                    .map_err(Self::refusal)?;
                chain.on_payload_attestation(&message)?;
                Ok(Spread::Broadcast)
            },
        )
        .await
    }

    /// The pool's attestations, each committee's best aggregate in the clock's fork.
    ///
    /// The optional slot and committee index parameters narrow the list.
    async fn pooled_attestations<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let query = Query::of(&request);
        let slot = query.optional_number("slot")?.map(Slot);
        let committee_index = query
            .optional_number("committee_index")?
            .map(CommitteeIndex);
        context
            .query(move |chain| {
                let fork = chain.config().fork_at(chain.store().current_epoch());
                let mut items = Vec::new();
                let groups = chain
                    .pool()
                    .attestations()
                    .groups()
                    .filter(|group| slot.is_none_or(|slot| group.data.slot == slot));
                for group in groups {
                    let committees = group.committees.iter().filter(|(index, _)| {
                        committee_index.is_none_or(|wanted| **index == wanted)
                    });
                    for (committee, votes) in committees {
                        let Some(best) = votes.best() else {
                            continue;
                        };
                        let packed = PackedAttestation {
                            data: group.data.clone(),
                            committees: vec![(*committee, best.bits.clone())],
                            signature: best.signature,
                            gain: 0,
                        };
                        if let Ok(json) = Self::attestation_json::<P>(fork, packed) {
                            items.push(json);
                        }
                    }
                }
                Ok(Self::versioned(fork, items))
            })
            .await
    }

    /// The pool's attester slashings, in the clock's fork.
    async fn pooled_attester_slashings<P: Preset>(
        context: ApiContext<P>,
        _request: Request,
    ) -> ApiResult {
        context
            .query(|chain| {
                let fork = chain.config().fork_at(chain.store().current_epoch());
                let state = chain.head_state()?.beacon();
                let items = chain
                    .pool()
                    .slashings()
                    .attesters_by_reach(state)
                    .into_iter()
                    .filter_map(|votes| Self::attester_slashing_json::<P>(fork, votes))
                    .collect();
                Ok(Self::versioned(fork, items))
            })
            .await
    }

    /// The pool's proposer slashings.
    async fn pooled_proposer_slashings<P: Preset>(
        context: ApiContext<P>,
        _request: Request,
    ) -> ApiResult {
        context
            .query(|chain| {
                let items = chain
                    .pool()
                    .slashings()
                    .proposers()
                    .map(ApiJson::to_json)
                    .collect();
                Ok(Reply::data(Json::Array(items), None))
            })
            .await
    }

    /// The pool's voluntary exits.
    async fn pooled_exits<P: Preset>(context: ApiContext<P>, _request: Request) -> ApiResult {
        context
            .query(|chain| {
                let items = chain
                    .pool()
                    .requests()
                    .exits()
                    .map(ApiJson::to_json)
                    .collect();
                Ok(Reply::data(Json::Array(items), None))
            })
            .await
    }

    /// The pool's credential changes.
    async fn pooled_changes<P: Preset>(context: ApiContext<P>, _request: Request) -> ApiResult {
        context
            .query(|chain| {
                let items = chain
                    .pool()
                    .requests()
                    .credential_changes()
                    .map(ApiJson::to_json)
                    .collect();
                Ok(Reply::data(Json::Array(items), None))
            })
            .await
    }

    /// Submits operations one by one, broadcasting those the rule accepts.
    async fn submit<P, T>(
        context: &ApiContext<P>,
        items: Vec<T>,
        kind: GossipKind,
        rule: impl Fn(&mut Chain<P>, T, u64) -> Result<Spread, ApiError> + Clone + Send + 'static,
    ) -> ApiResult
    where
        P: Preset,
        T: Ssz + Send + 'static,
    {
        let mut failures = Vec::<Failure>::new();
        for (position, item) in items.into_iter().enumerate() {
            if let Err(error) = Self::offer(context, item, kind, rule.clone()).await {
                failures.push((position, error.to_string()));
            }
        }
        Reply::submission(failures)
    }

    /// Submits one operation, broadcasting it when the rule accepts it as news.
    async fn offer<P, T>(
        context: &ApiContext<P>,
        item: T,
        kind: GossipKind,
        rule: impl FnOnce(&mut Chain<P>, T, u64) -> Result<Spread, ApiError> + Send + 'static,
    ) -> ApiResult
    where
        P: Preset,
        T: Ssz + Send + 'static,
    {
        let now = context.publisher.now_ms();
        let bytes = item.encode();
        let (spread, epoch) = context
            .query(move |chain| Ok((rule(chain, item, now)?, chain.store().current_epoch())))
            .await?;
        if spread == Spread::Broadcast {
            context.publisher.gossip(kind, epoch, bytes).await;
        }
        Ok(Response::new(StatusCode::OK))
    }

    /// The subnets of a sync committee member's seats.
    ///
    /// See `compute_subnets_for_sync_committee` in the Altair validator spec.
    fn sync_subnets<P: Preset>(
        chain: &Chain<P>,
        message: &SyncCommitteeMessage,
    ) -> Result<Vec<u64>, ApiError> {
        let state = chain.head_state()?.beacon();
        let committees = state
            .sync_committees()
            .ok_or_else(|| ApiError::bad_request("the head's fork has no sync committee"))?;
        let seats = SyncPool::<P>::seats(committees, message.validator_index)
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        let size = P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;
        let mut subnets: Vec<u64> = seats.iter().map(|seat| *seat as u64 / size).collect();
        subnets.dedup();
        Ok(subnets)
    }

    /// The fork a submission belongs to: the version header, or else the clock's.
    async fn fork<P: Preset>(
        context: &ApiContext<P>,
        request: &Request,
    ) -> Result<ForkName, ApiError> {
        match request.headers.get("eth-consensus-version") {
            Some(name) => ForkName::from_name(name)
                .ok_or_else(|| ApiError::bad_request(format!("unknown consensus version: {name}"))),
            None => {
                context
                    .query(|chain| Ok(chain.config().fork_at(chain.store().current_epoch())))
                    .await
            }
        }
    }

    /// The JSON of an aggregate in a fork's container.
    fn attestation_json<P: Preset>(
        fork: ForkName,
        packed: PackedAttestation,
    ) -> Result<Json, ApiError> {
        let invalid = |error: PoolError| ApiError::internal(error.to_string());
        Ok(match fork {
            ForkName::Phase0 => phase0::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Altair => altair::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Bellatrix => bellatrix::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Capella => capella::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Deneb => deneb::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Electra => electra::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Fulu => fulu::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Gloas => gloas::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
            ForkName::Hstar => hstar::BeaconState::<P>::attestation(packed)
                .map_err(invalid)?
                .to_json(),
        })
    }

    /// The JSON of conflicting votes in a fork's attester slashing, when they fit it.
    fn attester_slashing_json<P: Preset>(fork: ForkName, votes: &ConflictingVotes) -> Option<Json> {
        let json = match fork {
            ForkName::Phase0 => phase0::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Altair => altair::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Bellatrix => bellatrix::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Capella => capella::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Deneb => deneb::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Electra => electra::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Fulu => fulu::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Gloas => gloas::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
            ForkName::Hstar => hstar::BeaconState::<P>::attester_slashing(votes)
                .ok()?
                .to_json(),
        };
        Some(json)
    }

    /// A list reply tagged with its fork.
    fn versioned(fork: ForkName, items: Vec<Json>) -> Response {
        let body = Json::from([
            ("version", Json::from(fork.to_string())),
            ("data", Json::Array(items)),
        ]);
        Reply::json(StatusCode::OK, &body).with_header("eth-consensus-version", fork.to_string())
    }

    /// A gossip refusal, as the client's error.
    fn refusal(error: GossipError) -> ApiError {
        ApiError::bad_request(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axiom_beacon_json::ApiJsonError;
    use axiom_http::Method;
    use axiom_operation_pool::{Aggregate, Bits, CommitteeAggregate};
    use axiom_types::{
        BlsSignature, CommitteeIndex, Epoch, Minimal, Root, Slot, ValidatorIndex,
        capella::BlsToExecutionChange,
        phase0::{AttestationData, Checkpoint, VoluntaryExit},
    };

    use super::*;
    use crate::api::fixture::TestApi;

    /// An error reply's body.
    fn error(message: &str) -> Json {
        Json::from([
            ("code", Json::from(400_u64)),
            ("message", Json::from(message)),
        ])
    }

    /// The reply to a list whose items were all refused, for these reasons.
    fn indexed(reasons: &[String]) -> Json {
        let failures = reasons
            .iter()
            .enumerate()
            .map(|(index, message)| {
                Json::from([
                    ("index", Json::from(index as u64)),
                    ("message", Json::from(message.as_str())),
                ])
            })
            .collect::<Vec<_>>();
        Json::from([
            ("code", Json::from(400_u64)),
            (
                "message",
                Json::from(format!(
                    "{} of the submitted items were refused",
                    reasons.len()
                )),
            ),
            ("failures", Json::Array(failures)),
        ])
    }

    /// Why a JSON value does not decode as a type, as the routes report it.
    fn undecodable<T: ApiJson>(value: &Json) -> String {
        T::from_json(value)
            .err()
            .as_ref()
            .map(ApiJsonError::to_string)
            .unwrap()
    }

    #[test]
    fn a_repeated_aggregate_is_accepted_but_not_spread() {
        // A fresh aggregate goes out on its topic.
        assert_eq!(Spread::of_aggregate(Ok(())), Ok(Spread::Broadcast));

        // A second aggregator's copy of seen votes is valid news to no one.
        let seen = GossipError::ignore("already seen aggregate for this data");
        assert_eq!(Spread::of_aggregate(Err(seen)), Ok(Spread::Known));

        // A bad signature is refused, with the gossip rule's words.
        let forged = GossipError::reject("invalid aggregate signature");
        assert_eq!(
            Spread::of_aggregate(Err(forged)),
            Err(PoolRoutes::refusal(forged))
        );
    }

    #[test]
    fn slashings_and_exits_come_one_per_request() {
        let api = TestApi::phase0(8);
        // A list where one object is expected is refused before any check.
        let list = Json::Array(Vec::new());
        let routes = [
            (
                "/eth/v1/beacon/pool/voluntary_exits",
                undecodable::<SignedVoluntaryExit>(&list),
            ),
            (
                "/eth/v1/beacon/pool/proposer_slashings",
                undecodable::<ProposerSlashing>(&list),
            ),
            (
                "/eth/v2/beacon/pool/attester_slashings",
                undecodable::<phase0::AttesterSlashing<Minimal>>(&list),
            ),
        ];
        for (route, reason) in routes {
            assert_eq!(
                api.post(route, "[]"),
                (StatusCode::BAD_REQUEST, error(&reason)),
                "{route}"
            );
        }

        // One exit of validator 99, which does not exist, fails the gossip rules alone.
        // The refusal is a plain error, not an indexed one.
        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(0),
                validator_index: ValidatorIndex(99),
            },
            signature: BlsSignature::default(),
        };
        let now = api.now_ms();
        let checked = exit.clone();
        let reason = api.run(move |chain| {
            chain
                .validate_gossip(|validator| {
                    validator.voluntary_exit::<phase0::BeaconState<Minimal>>(&checked, now)
                })
                .unwrap_err()
                .to_string()
        });
        assert_eq!(
            api.post(
                "/eth/v1/beacon/pool/voluntary_exits",
                &exit.to_json().to_string()
            ),
            (StatusCode::BAD_REQUEST, error(&reason))
        );
    }

    #[test]
    fn refused_list_items_are_reported_by_index() {
        let api = TestApi::phase0(8);
        // Two credential changes before Capella: the gossip rules refuse each one.
        let changes: Vec<SignedBlsToExecutionChange> = [0, 99]
            .into_iter()
            .map(|index| SignedBlsToExecutionChange {
                message: BlsToExecutionChange {
                    validator_index: ValidatorIndex(index),
                    ..BlsToExecutionChange::default()
                },
                signature: BlsSignature::default(),
            })
            .collect();
        let now = api.now_ms();
        let checked = changes.clone();
        let reasons = api.run(move |chain| {
            checked
                .iter()
                .map(|change| {
                    chain
                        .validate_gossip(|validator| validator.bls_to_execution_change(change, now))
                        .unwrap_err()
                        .to_string()
                })
                .collect::<Vec<_>>()
        });
        let body = Json::Array(changes.iter().map(ApiJson::to_json).collect());
        assert_eq!(
            api.post(
                "/eth/v1/beacon/pool/bls_to_execution_changes",
                &body.to_string()
            ),
            (StatusCode::BAD_REQUEST, indexed(&reasons))
        );
    }

    #[test]
    fn payload_attestations_arrive_as_an_ssz_list() {
        let api = TestApi::gloas(8);
        // Two votes of validators 0 and 1 on a block the node never saw.
        let messages: Vec<PayloadAttestationMessage> = [0, 1]
            .into_iter()
            .map(|index| PayloadAttestationMessage {
                validator_index: ValidatorIndex(index),
                ..PayloadAttestationMessage::default()
            })
            .collect();
        let now = api.now_ms();
        let checked = messages.clone();
        let reasons = api.run(move |chain| {
            checked
                .iter()
                .map(|message| {
                    chain
                        .validate_gossip(|validator| {
                            validator.payload_attestation_message(message, now)
                        })
                        .unwrap_err()
                        .to_string()
                })
                .collect::<Vec<_>>()
        });
        // The SSZ list of two fixed-size messages is their encodings end to end.
        let body = messages.iter().flat_map(Ssz::encode).collect();
        let request = Request::new(Method::Post, "/eth/v1/beacon/pool/payload_attestations")
            .with_header("eth-consensus-version", "gloas")
            .with_body("application/octet-stream", body);
        assert_eq!(
            TestApi::parsed(&api.send(request)),
            (StatusCode::BAD_REQUEST, indexed(&reasons))
        );
    }

    #[test]
    fn pooled_attestations_are_filtered_by_slot_and_committee() {
        let api = TestApi::phase0(64);
        // One signer in each of three committee votes.
        // Slot 1 has committees 0 and 1, slot 2 has committee 0.
        let votes = [(1, 0), (1, 1), (2, 0)];
        let vote = |slot: u64, committee: u64| AttestationData {
            slot: Slot(slot),
            index: CommitteeIndex(committee),
            beacon_block_root: Root([7; 32]),
            source: Checkpoint::default(),
            target: Checkpoint::default(),
        };
        api.run(move |chain| {
            for (slot, committee) in votes {
                chain
                    .pool_mut()
                    .attestations_mut()
                    .insert(CommitteeAggregate {
                        data: vote(slot, committee),
                        committee: CommitteeIndex(committee),
                        aggregate: Aggregate {
                            bits: Bits::single(4, 1),
                            signature: BlsSignature::default(),
                        },
                    })
                    .unwrap();
            }
        });
        let attestation = |slot, committee| {
            let mut bits = phase0::AggregationBits::<Minimal>::with_len(4).unwrap();
            bits.set(1, true);
            phase0::Attestation::<Minimal> {
                aggregation_bits: bits,
                data: vote(slot, committee),
                signature: BlsSignature::default(),
            }
            .to_json()
            .to_string()
        };
        // The pool keeps no order, so the items compare as a set.
        let listed = |query: &str| {
            let (status, body) = api.get(&format!("/eth/v2/beacon/pool/attestations{query}"));
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.get("version"), Some(&Json::from("phase0")));
            body.get("data")
                .and_then(Json::as_array)
                .unwrap()
                .iter()
                .map(Json::to_string)
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            listed("?slot=1&committee_index=1"),
            BTreeSet::from([attestation(1, 1)])
        );
        assert_eq!(
            listed("?committee_index=0"),
            BTreeSet::from([attestation(1, 0), attestation(2, 0)])
        );
        assert_eq!(
            listed("?slot=1"),
            BTreeSet::from([attestation(1, 0), attestation(1, 1)])
        );
        assert_eq!(listed("").len(), 3);
    }
}
