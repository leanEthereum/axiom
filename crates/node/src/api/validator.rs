//! The validator namespace: duties, attestation data, aggregates, and block production.
//!
//! The node produces unsigned objects and takes signed ones; the validator client signs.
//! See the validator routes of beacon-APIs.

use std::collections::BTreeSet;

use axiom_beacon_json::{ApiJson, ForkedJson};
use axiom_block_production::{ProducedBlock, ProductionError, Proposal, RandaoCheck};
use axiom_bls::{PublicKey, Signature};
use axiom_fork_choice::NodePayload;
use axiom_http::{Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_operation_pool::{PackedAttestation, PoolError, PoolFork};
use axiom_ssz::{Ssz, U256};
use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, Bytes32, CommitteeIndex, Epoch, ExecutionAddress, ForkName, Preset, Root, Slot,
    ValidatorIndex, accessors::CoreState, altair, bellatrix,
    bellatrix::SignedValidatorRegistrationV1, capella, deneb, electra, fulu, gloas, phase0,
    phase0::AttestationData,
};

use super::{
    ApiContext,
    duties::{AttesterDuty, Duties, ProposerDuty, SyncDuty},
    query::{Body, Query},
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::{BlockOrder, Chain, ProposerError};

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
                "/eth/v1/validator/payload_attestation_data/{slot}",
                Self::payload_attestation_data::<P>,
            )
            .get(
                "/eth/v1/validator/duties/proposer/{epoch}",
                Self::proposer_duties::<P>,
            )
            .post(
                "/eth/v1/validator/duties/attester/{epoch}",
                Self::attester_duties::<P>,
            )
            .post(
                "/eth/v1/validator/duties/sync/{epoch}",
                Self::sync_duties::<P>,
            )
            .post(
                "/eth/v1/validator/duties/ptc/{epoch}",
                Self::ptc_duties::<P>,
            )
            .post(
                "/eth/v1/validator/prepare_beacon_proposer",
                Self::prepare_beacon_proposer::<P>,
            )
            .post(
                "/eth/v1/validator/register_validator",
                Self::register_validator::<P>,
            )
            .post(
                "/eth/v1/validator/beacon_committee_subscriptions",
                Self::subscriptions::<P>,
            )
            .post(
                "/eth/v1/validator/sync_committee_subscriptions",
                Self::subscriptions::<P>,
            )
    }

    /// Produces an unsigned block up to Fulu, full or blinded.
    ///
    /// The value headers state what the block's consensus rewards and its payload pay, in wei.
    async fn produce_v3<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let order = Self::block_order(&request)?;
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
        if Reply::accepts_ssz(&request) {
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
        let order = Self::block_order(&request)?;
        let include_payload = Query::of(&request).flag("include_payload")?;
        // The builder configuration must decode; its entries ask for bids this node does not fetch.
        if !Reply::sends_ssz(&request) {
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
            ProducedBlock::Gloas(block) => (block.to_json(), block.encode(), false),
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
        let mut response = if Reply::accepts_ssz(&request) {
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
        if Reply::accepts_ssz(&request) {
            return Ok(Reply::ssz(envelope.encode(), ForkName::Gloas));
        }
        let body = Json::from([
            ("version", Json::from(ForkName::Gloas.to_string())),
            ("data", envelope.to_json()),
        ]);
        Ok(Reply::json(StatusCode::OK, &body)
            .with_header("eth-consensus-version", ForkName::Gloas.to_string()))
    }

    /// The vote a validator of a committee signs at a slot.
    ///
    /// The source and target come from the head's state advanced to the slot.
    /// See "Attestation data" in the phase0 validator spec, and its Gloas payload signal.
    async fn attestation_data<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let query = Query::of(&request);
        let slot = Slot(query.number("slot")?);
        let committee_index = CommitteeIndex(query.number("committee_index")?);
        context
            .query(move |chain| {
                let data = Self::vote_at(chain, slot, committee_index)?;
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
                if Reply::accepts_ssz(&request) {
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
    /// See "Constructing the payload attestation message" in the Gloas validator spec.
    async fn payload_attestation_data<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let slot = Slot(Self::path_number(&request, "slot")?);
        context
            .query(move |chain| {
                let root = chain
                    .canonical_root(slot)?
                    .ok_or_else(|| ApiError::not_found("no block at the slot"))?;
                let envelope = chain.database().envelope(root)?;
                let data = gloas::PayloadAttestationData {
                    beacon_block_root: root,
                    slot,
                    payload_present: envelope.is_some(),
                    blob_data_available: envelope.is_some(),
                };
                Ok(Reply::data(data.to_json(), None))
            })
            .await
    }

    /// The proposers of an epoch.
    async fn proposer_duties<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Epoch(Self::path_number(&request, "epoch")?);
        context
            .query(move |chain| {
                let head = chain.head();
                let (dependent_root, duties) =
                    Duties::new(chain.head_state()?, chain.config(), head.root).proposers(epoch)?;
                let data = duties.iter().map(Self::proposer_json).collect::<Vec<_>>();
                Ok(Self::duties_reply(dependent_root, head.optimistic, data))
            })
            .await
    }

    /// The committee seats of some validators in an epoch.
    async fn attester_duties<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Epoch(Self::path_number(&request, "epoch")?);
        let validators = Self::indices(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let (dependent_root, duties) =
                    Duties::new(chain.head_state()?, chain.config(), head.root)
                        .attesters(epoch, &validators)?;
                let data = duties.iter().map(Self::attester_json).collect::<Vec<_>>();
                Ok(Self::duties_reply(dependent_root, head.optimistic, data))
            })
            .await
    }

    /// The sync committee seats of some validators in an epoch's period.
    async fn sync_duties<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Epoch(Self::path_number(&request, "epoch")?);
        let validators = Self::indices(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let duties = Duties::new(chain.head_state()?, chain.config(), head.root)
                    .sync(epoch, &validators)?;
                let data = duties.iter().map(Self::sync_json).collect::<Vec<_>>();
                let body = Json::from([
                    ("execution_optimistic", Json::from(head.optimistic)),
                    ("data", Json::Array(data)),
                ]);
                Ok(Reply::json(StatusCode::OK, &body))
            })
            .await
    }

    /// The payload timeliness committee seats of some validators in an epoch.
    async fn ptc_duties<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Epoch(Self::path_number(&request, "epoch")?);
        let validators = Self::indices(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let (dependent_root, duties) =
                    Duties::new(chain.head_state()?, chain.config(), head.root)
                        .ptc(epoch, &validators)?;
                let data = duties.iter().map(Self::proposer_json).collect::<Vec<_>>();
                Ok(Self::duties_reply(dependent_root, head.optimistic, data))
            })
            .await
    }

    /// Records the fee recipients validators name for their coming proposals.
    async fn prepare_beacon_proposer<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let value = Body(&request).json()?;
        let items = value
            .as_array()
            .ok_or_else(|| ApiError::bad_request("body is not a JSON array"))?;
        let mut recipients = Vec::with_capacity(items.len());
        for (position, item) in items.iter().enumerate() {
            let invalid = |what: &str| ApiError::bad_request(format!("item {position}: {what}"));
            let index = item
                .get("validator_index")
                .and_then(Json::as_str)
                .and_then(|text| text.parse().ok())
                .ok_or_else(|| invalid("validator_index is not a decimal string"))?;
            let address = item
                .get("fee_recipient")
                .and_then(Json::as_str)
                .and_then(|text| <[u8; 20]>::from_data(text).ok())
                .ok_or_else(|| invalid("fee_recipient is not a 20-byte address"))?;
            recipients.push((ValidatorIndex(index), ExecutionAddress(address)));
        }
        // Validators the head does not know cannot propose, so naming them is an error.
        let count = recipients.len();
        let largest = recipients.iter().map(|(index, _)| *index).max();
        context
            .query(move |chain| {
                let registry_size = chain.head_state()?.beacon().validators().len();
                match largest {
                    Some(index) if index.as_usize() >= registry_size => Err(ApiError::bad_request(
                        format!("validator {index} is not in the registry of {registry_size}"),
                    )),
                    _ => Ok(count),
                }
            })
            .await?;
        context.proposer.prepare(recipients);
        Ok(Response::new(StatusCode::OK))
    }

    /// Records the builder registrations validators signed.
    ///
    /// Each registration must carry its key's signature in the application builder domain.
    /// See `verify_registration_signature` in the Bellatrix builder spec.
    async fn register_validator<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let registrations: Vec<SignedValidatorRegistrationV1> = Body(&request).items()?;
        let domain = context
            .query(|chain| Ok(chain.config().application_builder_domain()))
            .await?;
        let mut accepted = Vec::with_capacity(registrations.len());
        for (position, signed) in registrations.into_iter().enumerate() {
            let root = phase0::SigningData::signing_root(&signed.message, domain);
            let valid = PublicKey::from_bytes(&signed.message.pubkey.0)
                .ok()
                .zip(Signature::from_bytes(&signed.signature.0).ok())
                .is_some_and(|(key, signature)| signature.verify(&key, root.as_ref()));
            if !valid {
                return Err(ApiError::bad_request(format!(
                    "registration {position} is not signed by its key"
                )));
            }
            accepted.push(signed.message);
        }
        context.proposer.register(accepted);
        Ok(Response::new(StatusCode::OK))
    }

    /// Accepts committee subscriptions.
    ///
    /// The node joins the attestation subnets of its own identity only.
    /// An aggregator on another subnet still receives the aggregates of its committee.
    async fn subscriptions<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let value = Body(&request).json()?;
        if value.as_array().is_none() {
            return Err(ApiError::bad_request("body is not a JSON array"));
        }
        // A subscription needs a running chain, whose subnets it would join.
        context.query(|_| Ok(())).await?;
        Ok(Response::new(StatusCode::OK))
    }

    /// The vote of a committee at a slot, on the head as the slot sees it.
    fn vote_at<P: Preset>(
        chain: &mut Chain<P>,
        slot: Slot,
        committee_index: CommitteeIndex,
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
            committee_index
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
            ProducedBlock::Gloas(block) => block.to_json(),
            ProducedBlock::Blinded(block) => ForkedJson::to_json(block),
        }
    }

    /// The proposal a block request asks for, from its path and query.
    fn block_order(request: &Request) -> Result<BlockOrder, ApiError> {
        let slot = Slot(Self::path_number(request, "slot")?);
        let query = Query::of(request);
        let randao_reveal = BlsSignature(query.bytes::<96>("randao_reveal")?);
        let graffiti = Bytes32(query.optional_bytes::<32>("graffiti")?.unwrap_or_default());
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
        query.optional_number("builder_boost_factor")?;
        Ok(BlockOrder {
            slot,
            randao_reveal,
            graffiti,
            randao,
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

    /// The validator indices of a duties request body: a JSON array of decimal strings.
    fn indices(request: &Request) -> Result<BTreeSet<ValidatorIndex>, ApiError> {
        let value = Body(request).json()?;
        let items = value
            .as_array()
            .ok_or_else(|| ApiError::bad_request("body is not a JSON array"))?;
        items
            .iter()
            .map(|item| {
                item.as_str()
                    .and_then(|text| text.parse().ok())
                    .map(ValidatorIndex)
                    .ok_or_else(|| ApiError::bad_request("validator index is not a decimal string"))
            })
            .collect()
    }

    /// A duties reply, with the root the duties depend on.
    fn duties_reply(dependent_root: Root, optimistic: bool, data: Vec<Json>) -> Response {
        let body = Json::from([
            ("dependent_root", Reply::text(&dependent_root)),
            ("execution_optimistic", Json::from(optimistic)),
            ("data", Json::Array(data)),
        ]);
        Reply::json(StatusCode::OK, &body)
    }

    /// A proposer or payload committee duty in JSON.
    fn proposer_json(duty: &ProposerDuty) -> Json {
        Json::from([
            ("pubkey", Reply::text(&duty.pubkey)),
            ("validator_index", Reply::number(duty.validator_index.0)),
            ("slot", Reply::number(duty.slot.0)),
        ])
    }

    /// An attester duty in JSON.
    fn attester_json(duty: &AttesterDuty) -> Json {
        Json::from([
            ("pubkey", Reply::text(&duty.pubkey)),
            ("validator_index", Reply::number(duty.validator_index.0)),
            ("committee_index", Reply::number(duty.committee_index.0)),
            ("committee_length", Reply::number(duty.committee_length)),
            ("committees_at_slot", Reply::number(duty.committees_at_slot)),
            (
                "validator_committee_index",
                Reply::number(duty.validator_committee_index),
            ),
            ("slot", Reply::number(duty.slot.0)),
        ])
    }

    /// A sync committee duty in JSON.
    fn sync_json(duty: &SyncDuty) -> Json {
        Json::from([
            ("pubkey", Reply::text(&duty.pubkey)),
            ("validator_index", Reply::number(duty.validator_index.0)),
            (
                "validator_sync_committee_indices",
                Json::Array(
                    duty.seats
                        .iter()
                        .map(|seat| Reply::number(*seat as u64))
                        .collect(),
                ),
            ),
        ])
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
            ProposerError::ChainStopped | ProposerError::NoEngine | ProposerError::Engine(_) => {
                Self::unavailable(error.to_string())
            }
            ProposerError::SlotOutOfRange { .. }
            | ProposerError::WrongRoute(_)
            | ProposerError::Production(ProductionError::InvalidRandao { .. }) => {
                Self::bad_request(error.to_string())
            }
            other => Self::internal(other.to_string()),
        }
    }
}
