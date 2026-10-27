//! The validator namespace: attestation data, aggregates, payload votes, and block production.
//!
//! The node produces unsigned objects and takes signed ones; the validator client signs.
//! See the validator routes of beacon-APIs.

use axiom_beacon_json::{ApiJson, ForkedJson};
use axiom_block_production::{BuilderBoost, ProducedBlock, ProductionError, Proposal, RandaoCheck};
use axiom_bls::Signature;
use axiom_builder_client::{RevealedBlobs, UnblindedBlock};
use axiom_fork_choice::NodePayload;
use axiom_http::{Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_operation_pool::{PackedAttestation, PoolError, PoolFork};
use axiom_ssz::{Ssz, U256};
use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, Bytes32, CommitteeIndex, ForkName, Preset, Root, Slot, accessors::CoreState,
    altair, bellatrix, capella, combined, combined::SignedBlindedBeaconBlock, deneb, electra, fulu,
    gloas, hstar, phase0, phase0::AttestationData,
};

use super::{
    ApiContext,
    encoding::Encoding,
    query::{Body, Query},
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::{
    BlockOrder, Chain, ChainStopped, GraffitiPolicy, Proposal as PublishProposal, ProposerError,
    PublishError, Published,
};

/// Wei per Gwei, to state consensus rewards in the unit the API uses.
const WEI_PER_GWEI: u128 = 1_000_000_000;

/// Routes under `/eth/v1/validator` and the block production routes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ValidatorRoutes;

impl ValidatorRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v3/validator/blocks/{slot}", Self::produce_v3::<P>)
            .post("/eth/v4/validator/blocks/{slot}", Self::produce_v4::<P>)
            .get(
                "/eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}",
                Self::envelope::<P>,
            )
            .get(
                "/eth/v1/validator/attestation_data",
                Self::attestation_data::<P>,
            )
            .get(
                "/eth/v2/validator/aggregate_attestation",
                Self::aggregate_attestation::<P>,
            )
            .get(
                "/eth/v1/validator/sync_committee_contribution",
                Self::sync_committee_contribution::<P>,
            )
            .get(
                "/eth/v1/validator/payload_attestation_data",
                Self::payload_attestation_data::<P>,
            )
            .post("/eth/v2/beacon/blinded_blocks", Self::publish_blinded::<P>)
    }

    /// Produces an unsigned block up to Fulu, full or blinded.
    ///
    /// The value headers state what the block's consensus rewards and its payload pay, in wei.
    async fn produce_v3<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let order = Self::block_order(&context, &request).await?;
        let fork = Self::slot_fork(&context, order.slot).await?;
        if fork.separates_payloads() {
            return Err(ApiError::bad_request(format!(
                "{fork} blocks are produced by the v4 route"
            )));
        }
        let proposal = context
            .proposer
            .produce(order)
            .await
            .map_err(ApiError::from)?;
        let blinded = proposal.block.is_blinded();
        let headers = [
            ("eth-execution-payload-blinded", blinded.to_string()),
            (
                "eth-execution-payload-value",
                Self::wei(proposal.execution_value),
            ),
            ("eth-consensus-block-value", Self::gwei_in_wei(&proposal)),
        ];
        if Encoding::accepted(&request, true)? == Encoding::Ssz {
            let mut response = Reply::ssz(proposal.block.encode(), fork);
            for (name, value) in headers {
                response = response.with_header(name, value);
            }
            return Ok(response);
        }
        let body = Json::from([
            ("version", Json::from(fork.to_string())),
            ("execution_payload_blinded", Json::from(blinded)),
            (
                "execution_payload_value",
                Json::from(Self::wei(proposal.execution_value)),
            ),
            (
                "consensus_block_value",
                Json::from(Self::gwei_in_wei(&proposal)),
            ),
            ("data", Self::produced_json(&proposal.block)),
        ]);
        let mut response = Reply::json(StatusCode::OK, &body)
            .with_header("eth-consensus-version", fork.to_string());
        for (name, value) in headers {
            response = response.with_header(name, value);
        }
        Ok(response)
    }

    /// Produces an unsigned Gloas block, self-built, with its envelope when asked.
    ///
    /// Without the payload, the node keeps the envelope for the validator to fetch.
    async fn produce_v4<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let order = Self::block_order(&context, &request).await?;
        let include_payload = Query::of(&request).flag("include_payload")?;
        // The builder configuration must decode; its entries ask for bids this node does not fetch.
        if Encoding::of_body(&request, true)? == Encoding::Json {
            let config = Body(&request).json()?;
            if config.get("builders").and_then(Json::as_array).is_none() {
                return Err(ApiError::bad_request(
                    "builder configuration has no builders list",
                ));
            }
        }
        let fork = Self::slot_fork(&context, order.slot).await?;
        if !fork.separates_payloads() {
            return Err(ApiError::bad_request(format!(
                "{fork} blocks are produced by the v3 route"
            )));
        }
        let proposal = context
            .proposer
            .produce(order)
            .await
            .map_err(ApiError::from)?;
        let (data, ssz, included) = match &proposal.block {
            ProducedBlock::GloasContents(contents) if include_payload => {
                (contents.to_json(), contents.encode(), true)
            }
            ProducedBlock::GloasContents(contents) => {
                (contents.block.to_json(), contents.block.encode(), false)
            }
            ProducedBlock::HstarContents(contents) if include_payload => {
                (contents.to_json(), contents.encode(), true)
            }
            ProducedBlock::HstarContents(contents) => {
                (contents.block.to_json(), contents.block.encode(), false)
            }
            ProducedBlock::Gloas(block) => (block.to_json(), block.encode(), false),
            ProducedBlock::Hstar(block) => (block.to_json(), block.encode(), false),
            other => {
                return Err(ApiError::internal(format!(
                    "unexpected {} block",
                    other.fork_name()
                )));
            }
        };
        let headers = [
            ("eth-consensus-block-value", Self::gwei_in_wei(&proposal)),
            (
                "eth-execution-payload-value",
                Self::wei(proposal.execution_value),
            ),
            ("eth-execution-payload-included", included.to_string()),
        ];
        let mut response = if Encoding::accepted(&request, true)? == Encoding::Ssz {
            Reply::ssz(ssz, fork)
        } else {
            let body = Json::from([
                ("version", Json::from(fork.to_string())),
                (
                    "consensus_block_value",
                    Json::from(Self::gwei_in_wei(&proposal)),
                ),
                (
                    "execution_payload_value",
                    Json::from(Self::wei(proposal.execution_value)),
                ),
                ("execution_payload_included", Json::from(included)),
                ("data", data),
            ]);
            Reply::json(StatusCode::OK, &body)
                .with_header("eth-consensus-version", fork.to_string())
        };
        for (name, value) in headers {
            response = response.with_header(name, value);
        }
        Ok(response)
    }

    /// The envelope of a self-built Gloas block, kept since its production.
    async fn envelope<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let slot = Slot(Self::path_number(&request, "slot")?);
        let root = Self::path_root(&request, "beacon_block_root")?;
        let fork = Self::slot_fork(&context, slot).await?;
        if !fork.separates_payloads() {
            return Err(ApiError::bad_request(format!(
                "{fork} blocks carry their payload"
            )));
        }
        let envelope = context
            .proposer
            .envelope(slot, root)
            .ok_or_else(|| ApiError::not_found("no envelope cached for the slot and block"))?;
        if Encoding::accepted(&request, true)? == Encoding::Ssz {
            return Ok(Reply::ssz(envelope.encode(), ForkName::Gloas));
        }
        let body = Json::from([
            ("version", Json::from(ForkName::Gloas.to_string())),
            ("data", envelope.to_json()),
        ]);
        Ok(Reply::json(StatusCode::OK, &body)
            .with_header("eth-consensus-version", ForkName::Gloas.to_string()))
    }

    /// The vote a validator of a committee signs at a slot, as JSON or SSZ.
    ///
    /// The source and target come from the head's state advanced to the slot.
    /// The committee index matters before Electra only, so it may be left out from Electra on.
    /// An optimistic head is refused: a vote must not attest to a payload no engine validated.
    /// See "Attestation data" in the phase0 validator spec, and its Gloas payload signal.
    async fn attestation_data<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let query = Query::of(&request);
        let slot = Slot(query.number("slot")?);
        let committee_index = query
            .optional_number("committee_index")?
            .map(CommitteeIndex);
        let ssz = Encoding::accepted(&request, true)? == Encoding::Ssz;
        context
            .query(move |chain| {
                if chain.head().optimistic {
                    return Err(ApiError::unavailable(
                        "the head is optimistic: its payload is not validated yet",
                    ));
                }
                let data = Self::vote_at(chain, slot, committee_index)?;
                if ssz {
                    let fork = chain.config().fork_at(slot.epoch::<P>());
                    return Ok(Reply::ssz(data.encode(), fork));
                }
                Ok(Reply::data(data.to_json(), None))
            })
            .await
    }

    /// The best aggregate the pool holds for a vote and committee, in the slot's fork.
    async fn aggregate_attestation<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let query = Query::of(&request);
        let root = Root(query.bytes::<32>("attestation_data_root")?);
        let slot = Slot(query.number("slot")?);
        let committee = CommitteeIndex(query.number("committee_index")?);
        context
            .query(move |chain| {
                let fork = chain.config().fork_at(slot.epoch::<P>());
                let (data, aggregate) = chain
                    .pool()
                    .attestations()
                    .best_aggregate(&root, committee)
                    .ok_or_else(|| {
                        ApiError::not_found("no aggregate for the vote and committee")
                    })?;
                let packed = PackedAttestation {
                    data: data.clone(),
                    committees: vec![(committee, aggregate.bits.clone())],
                    signature: aggregate.signature,
                    gain: 0,
                };
                let (json, ssz) = Self::attestation_of::<P>(fork, packed)?;
                if Encoding::accepted(&request, true)? == Encoding::Ssz {
                    return Ok(Reply::ssz(ssz, fork));
                }
                let body = Json::from([("version", Json::from(fork.to_string())), ("data", json)]);
                Ok(Reply::json(StatusCode::OK, &body)
                    .with_header("eth-consensus-version", fork.to_string()))
            })
            .await
    }

    /// The best contribution of a sync subcommittee for a root at a slot.
    async fn sync_committee_contribution<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let query = Query::of(&request);
        let slot = Slot(query.number("slot")?);
        let subcommittee = query.number("subcommittee_index")?;
        let root = Root(query.bytes::<32>("beacon_block_root")?);
        context
            .query(move |chain| {
                let contribution = chain
                    .pool()
                    .sync()
                    .contribution(slot, root, subcommittee)
                    .ok_or_else(|| ApiError::not_found("no contribution for the subcommittee"))?;
                Ok(Reply::data(contribution.to_json(), None))
            })
            .await
    }

    /// What a payload timeliness committee member attests at a slot: the block and its payload.
    ///
    /// Without a block at the slot there is nothing to attest, which the empty 204 reply says.
    /// See `producePayloadAttestationData` in the beacon API.
    /// See "Constructing the payload attestation message" in the Gloas validator spec.
    async fn payload_attestation_data<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let slot = Slot(Query::of(&request).number("slot")?);
        let encoding = Encoding::accepted(&request, true)?;
        context
            .query(move |chain| {
                let fork = chain.config().fork_at(slot.epoch::<P>());
                if !fork.separates_payloads() {
                    return Err(ApiError::bad_request(format!(
                        "{fork} blocks carry their payload, so no payload is attested"
                    )));
                }
                let Some(root) = chain.canonical_root(slot)? else {
                    return Ok(Reply::no_content());
                };
                let envelope = chain.database().envelope(root)?;
                let data = gloas::PayloadAttestationData {
                    beacon_block_root: root,
                    slot,
                    payload_present: envelope.is_some(),
                    blob_data_available: envelope.is_some(),
                };
                Ok(Reply::typed(encoding, fork, None, &data))
            })
            .await
    }

    /// Publishes a signed blinded block, once its builder reveals the payload.
    ///
    /// The revealed payload must match the signed header, so the signature covers the full block.
    /// Statuses follow the full block route: 200 imported, 202 broadcast only, 400 invalid.
    async fn publish_blinded<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let named = request
            .headers
            .get("eth-consensus-version")
            .ok_or_else(|| ApiError::bad_request("missing consensus version header"))?;
        let fork = ForkName::from_name(named)
            .ok_or_else(|| ApiError::bad_request(format!("unknown consensus version: {named}")))?;
        let block = if Encoding::of_body(&request, true)? == Encoding::Ssz {
            SignedBlindedBeaconBlock::<P>::decode(&request.body, fork)
                .map_err(|error| ApiError::bad_request(error.to_string()))?
        } else {
            SignedBlindedBeaconBlock::<P>::from_json_in(fork, &Body(&request).json()?)
                .map_err(|error| ApiError::bad_request(error.to_string()))?
        };
        let revealed = context
            .proposer
            .reveal(&block)
            .await
            .map_err(ApiError::from)?;
        let proposal = Self::full_proposal(revealed)?;
        match context.publisher.publish(proposal).await {
            Ok(Published::Imported(_)) => Ok(Response::new(StatusCode::OK)),
            Ok(Published::BroadcastOnly(_)) => Ok(Response::new(StatusCode::ACCEPTED)),
            Err(PublishError::ChainStopped) => Err(ChainStopped.into()),
            Err(error) => Err(ApiError::bad_request(error.to_string())),
        }
    }

    /// The publishable form of an unblinded block, with the blobs its builder revealed.
    fn full_proposal<P: Preset>(
        revealed: UnblindedBlock<P>,
    ) -> Result<PublishProposal<P>, ApiError> {
        let mismatch = || ApiError::internal("revealed blobs of another fork than the block");
        Ok(match (revealed.block, revealed.blobs) {
            (combined::SignedBeaconBlock::Deneb(block), Some(RevealedBlobs::Deneb(bundle))) => {
                PublishProposal::DenebBlobs(deneb::SignedBlockContents {
                    signed_block: block,
                    kzg_proofs: bundle.proofs,
                    blobs: bundle.blobs,
                })
            }
            (combined::SignedBeaconBlock::Electra(block), Some(RevealedBlobs::Deneb(bundle))) => {
                PublishProposal::ElectraBlobs(electra::SignedBlockContents {
                    signed_block: block,
                    kzg_proofs: bundle.proofs,
                    blobs: bundle.blobs,
                })
            }
            (combined::SignedBeaconBlock::Fulu(block), Some(RevealedBlobs::Fulu(bundle))) => {
                PublishProposal::Columns(fulu::SignedBlockContents {
                    signed_block: block,
                    kzg_proofs: bundle.proofs,
                    blobs: bundle.blobs,
                })
            }
            (block, None) => PublishProposal::Block(block),
            _ => return Err(mismatch()),
        })
    }

    /// The vote of a committee at a slot, on the head as the slot sees it.
    ///
    /// # Errors
    ///
    /// Fails for a slot more than an epoch past the head, or before Electra without a committee.
    fn vote_at<P: Preset>(
        chain: &mut Chain<P>,
        slot: Slot,
        committee_index: Option<CommitteeIndex>,
    ) -> Result<AttestationData, ApiError> {
        let head = chain.head();
        if slot.epoch::<P>() > head.slot.epoch::<P>() + 1 {
            return Err(ApiError::bad_request(format!(
                "slot {slot} is more than an epoch past the head at {}",
                head.slot
            )));
        }
        let config = chain.config().clone();
        let fork = config.fork_at(slot.epoch::<P>());
        let mut state: State<P> = chain.head_state()?.clone();
        if slot > state.beacon().slot() {
            state
                .process_slots(&config, slot)
                .map_err(|error| ApiError::internal(error.to_string()))?;
        }
        let beacon = state.beacon();
        let epoch = slot.epoch::<P>();
        // A vote at the epoch's first slot, or past the head, targets the head itself.
        let target_root = if epoch.start_slot::<P>() >= head.slot.max(Slot(1)) {
            head.root
        } else {
            beacon.block_root(epoch).unwrap_or(head.root)
        };
        let index = if fork.separates_payloads() {
            // Gloas: zero for the slot's own block or an empty payload, one for a full payload.
            let full = head.slot != slot && chain.head_node()?.payload == NodePayload::Full;
            CommitteeIndex(u64::from(full))
        } else if !fork.names_committee_in_vote() {
            CommitteeIndex(0)
        } else {
            committee_index.ok_or_else(|| {
                ApiError::bad_request(format!(
                    "{fork} votes name their committee, so committee_index is required"
                ))
            })?
        };
        Ok(AttestationData {
            slot,
            index,
            beacon_block_root: head.root,
            source: beacon.current_justified_checkpoint(),
            target: phase0::Checkpoint {
                epoch,
                root: target_root,
            },
        })
    }

    /// An aggregate in the container of a fork, as JSON and SSZ.
    fn attestation_of<P: Preset>(
        fork: ForkName,
        packed: PackedAttestation,
    ) -> Result<(Json, Vec<u8>), ApiError> {
        let invalid = |error: PoolError| ApiError::internal(error.to_string());
        Ok(match fork {
            ForkName::Phase0 => {
                Self::pair(&phase0::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Altair => {
                Self::pair(&altair::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Bellatrix => {
                Self::pair(&bellatrix::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Capella => {
                Self::pair(&capella::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Deneb => {
                Self::pair(&deneb::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Electra => {
                Self::pair(&electra::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Fulu => {
                Self::pair(&fulu::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Gloas => {
                Self::pair(&gloas::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
            ForkName::Hstar => {
                Self::pair(&hstar::BeaconState::<P>::attestation(packed).map_err(invalid)?)
            }
        })
    }

    /// A value's JSON and SSZ forms.
    fn pair<T: ApiJson + Ssz>(value: &T) -> (Json, Vec<u8>) {
        (value.to_json(), value.encode())
    }

    /// The JSON of a produced block, in the shape of its fork's production response.
    fn produced_json<P: Preset>(block: &ProducedBlock<P>) -> Json {
        match block {
            ProducedBlock::Phase0(block) => block.to_json(),
            ProducedBlock::Altair(block) => block.to_json(),
            ProducedBlock::Bellatrix(block) => block.to_json(),
            ProducedBlock::Capella(block) => block.to_json(),
            ProducedBlock::Deneb(contents) => contents.to_json(),
            ProducedBlock::Electra(contents) => contents.to_json(),
            ProducedBlock::Fulu(contents) => contents.to_json(),
            ProducedBlock::GloasContents(contents) => contents.to_json(),
            ProducedBlock::HstarContents(contents) => contents.to_json(),
            ProducedBlock::Gloas(block) => block.to_json(),
            ProducedBlock::Hstar(block) => block.to_json(),
            ProducedBlock::Blinded(block) => ForkedJson::to_json(block),
        }
    }

    /// The proposal a block request asks for, from its path and query.
    ///
    /// The graffiti weighs the request's text and policy against the node's choices.
    /// The policy parameter extends the standard routes; a request without it appends versions.
    async fn block_order<P: Preset>(
        context: &ApiContext<P>,
        request: &Request,
    ) -> Result<BlockOrder, ApiError> {
        let slot = Slot(Self::path_number(request, "slot")?);
        let query = Query::of(request);
        let randao_reveal = BlsSignature(query.bytes::<96>("randao_reveal")?);
        let requested = query.optional_bytes::<32>("graffiti")?.map(Bytes32);
        let policy = query
            .text("graffiti_policy")
            .map(str::parse::<GraffitiPolicy>)
            .transpose()
            .map_err(ApiError::bad_request)?
            .unwrap_or_default();
        let graffiti = context.proposer.block_graffiti(requested, policy).await;
        // Skipping needs the point at infinity as the reveal, so no real reveal is ignored.
        let randao = if query.flag("skip_randao_verification")? {
            if randao_reveal.0 != Signature::INFINITY_BYTES {
                return Err(ApiError::bad_request(
                    "skipping randao verification needs the point at infinity as the reveal",
                ));
            }
            RandaoCheck::Skip
        } else {
            RandaoCheck::Verify
        };
        let boost = query
            .optional_number("builder_boost_factor")?
            .map_or(BuilderBoost::NEUTRAL, BuilderBoost);
        Ok(BlockOrder {
            slot,
            randao_reveal,
            graffiti,
            randao,
            boost,
        })
    }

    /// The fork of a slot.
    async fn slot_fork<P: Preset>(
        context: &ApiContext<P>,
        slot: Slot,
    ) -> Result<ForkName, ApiError> {
        context
            .query(move |chain| Ok(chain.config().fork_at(slot.epoch::<P>())))
            .await
    }

    /// A decimal path parameter.
    fn path_number(request: &Request, name: &str) -> Result<u64, ApiError> {
        let text = request
            .param(name)
            .ok_or_else(|| ApiError::bad_request(format!("missing {name}")))?;
        text.parse()
            .map_err(|_| ApiError::bad_request(format!("{name} is not a uint64: {text}")))
    }

    /// A root path parameter.
    fn path_root(request: &Request, name: &str) -> Result<Root, ApiError> {
        let text = request
            .param(name)
            .ok_or_else(|| ApiError::bad_request(format!("missing {name}")))?;
        <[u8; 32]>::from_data(text)
            .map(Root)
            .map_err(|_| ApiError::bad_request(format!("{name} is not a root: {text}")))
    }

    /// A wei amount as a decimal string.
    fn wei(value: U256) -> String {
        value
            .to_json()
            .as_str()
            .map(str::to_owned)
            .unwrap_or_default()
    }

    /// The consensus value of a proposal, in wei, as a decimal string.
    fn gwei_in_wei<P: Preset>(proposal: &Proposal<P>) -> String {
        (u128::from(proposal.consensus_value.0) * WEI_PER_GWEI).to_string()
    }
}

impl From<ProposerError> for ApiError {
    fn from(error: ProposerError) -> Self {
        match error {
            ProposerError::ChainStopped
            | ProposerError::NoEngine
            | ProposerError::Engine(_)
            | ProposerError::NoBuilder
            | ProposerError::Builder(_) => Self::unavailable(error.to_string()),
            ProposerError::SlotOutOfRange { .. }
            | ProposerError::WrongRoute(_)
            | ProposerError::Production(ProductionError::InvalidRandao { .. }) => {
                Self::bad_request(error.to_string())
            }
            other => Self::internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_http::Method;
    use axiom_types::Epoch;

    use super::*;
    use crate::api::fixture::TestApi;

    #[test]
    fn payload_attestation_data_takes_its_slot_from_the_query() {
        let api = TestApi::gloas(8);
        let genesis = api.run(|chain| chain.head().root);

        // Slot 0 holds the genesis block, whose payload no envelope revealed.
        let response = api.send(Request::new(
            Method::Get,
            "/eth/v1/validator/payload_attestation_data?slot=0",
        ));
        assert_eq!(response.headers.get("eth-consensus-version"), Some("gloas"));
        let data = gloas::PayloadAttestationData {
            beacon_block_root: genesis,
            slot: Slot(0),
            payload_present: false,
            blob_data_available: false,
        };
        let expected = Json::from([("version", Json::from("gloas")), ("data", data.to_json())]);
        assert_eq!(TestApi::parsed(&response), (StatusCode::OK, expected));

        // No block was seen at slot 1, so there is nothing to attest.
        api.at_slot(Slot(1));
        let response = api.send(Request::new(
            Method::Get,
            "/eth/v1/validator/payload_attestation_data?slot=1",
        ));
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        assert_eq!(response.body, Vec::<u8>::new());

        // The slot is required, and the path no longer carries it.
        assert_eq!(
            api.get("/eth/v1/validator/payload_attestation_data"),
            (
                StatusCode::BAD_REQUEST,
                Json::parse(r#"{"code":400,"message":"missing query parameter slot"}"#).unwrap()
            )
        );
        assert_eq!(
            api.get("/eth/v1/validator/payload_attestation_data/0").0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn payload_attestation_data_exists_from_gloas_on() {
        let api = TestApi::phase0(8);
        assert_eq!(
            api.get("/eth/v1/validator/payload_attestation_data?slot=0"),
            (
                StatusCode::BAD_REQUEST,
                Json::parse(
                    r#"{"code":400,"message":"phase0 blocks carry their payload, so no payload is attested"}"#
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn attestation_data_needs_a_committee_only_where_votes_name_one() {
        // Phase0 votes name their committee, so leaving it out is an error.
        let api = TestApi::phase0(64);
        assert_eq!(
            api.get("/eth/v1/validator/attestation_data?slot=0"),
            (
                StatusCode::BAD_REQUEST,
                Json::parse(
                    r#"{"code":400,"message":"phase0 votes name their committee, so committee_index is required"}"#
                )
                .unwrap()
            )
        );

        // Committee 1 at genesis: source and target both rest on the genesis block.
        let genesis = api.run(|chain| chain.head().root);
        let vote = AttestationData {
            slot: Slot(0),
            index: CommitteeIndex(1),
            beacon_block_root: genesis,
            source: phase0::Checkpoint::default(),
            target: phase0::Checkpoint {
                epoch: Epoch(0),
                root: genesis,
            },
        };
        assert_eq!(
            api.get("/eth/v1/validator/attestation_data?slot=0&committee_index=1"),
            (StatusCode::OK, Json::from([("data", vote.to_json())]))
        );

        // A Gloas vote signals the payload in its index, so no committee is asked for.
        let api = TestApi::gloas(64);
        let genesis = api.run(|chain| chain.head().root);
        let vote = AttestationData {
            index: CommitteeIndex(0),
            beacon_block_root: genesis,
            target: phase0::Checkpoint {
                epoch: Epoch(0),
                root: genesis,
            },
            ..vote
        };
        assert_eq!(
            api.get("/eth/v1/validator/attestation_data?slot=0"),
            (StatusCode::OK, Json::from([("data", vote.to_json())]))
        );
    }
}
