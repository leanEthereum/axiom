//! The beacon namespace: genesis, blocks, headers, blob data, and publishing.

use std::collections::BTreeSet;

use axiom_beacon_json::{ApiJson, ForkedJson};
use axiom_http::{Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_ssz::{Length, Ssz};
use axiom_types::{
    BlobData, BlobIndex, ColumnIndex, ForkName, KzgCommitment, Preset, Root, Slot, VersionedHash,
    accessors::CoreState,
    combined::{SignedBeaconBlock, SignedBlindedBeaconBlock},
    deneb::{Blob, BlobSidecar},
    gloas::SignedExecutionPayloadEnvelope,
};
use tracing::warn;

use super::{
    ApiContext,
    encoding::Encoding,
    ids::BlockId,
    query::Query,
    reply::{ApiError, ApiResult, Freshness, Reply, Routes},
};
use crate::{Chain, ChainStopped, Proposal, PublishError, Published};

/// Routes under `/eth/v1/beacon` and `/eth/v2/beacon`, states and light clients aside.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BeaconRoutes;

impl BeaconRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/beacon/genesis", Self::genesis::<P>)
            .get("/eth/v1/beacon/headers", Self::headers::<P>)
            .get("/eth/v1/beacon/headers/{block_id}", Self::header::<P>)
            .get(
                "/eth/v1/beacon/blocks/{block_id}/root",
                Self::block_root::<P>,
            )
            .get("/eth/v2/beacon/blocks/{block_id}", Self::block::<P>)
            .get(
                "/eth/v1/beacon/blinded_blocks/{block_id}",
                Self::blinded_block::<P>,
            )
            .get(
                "/eth/v2/beacon/blocks/{block_id}/attestations",
                Self::attestations::<P>,
            )
            .get(
                "/eth/v1/beacon/blob_sidecars/{block_id}",
                Self::blob_sidecars::<P>,
            )
            .get("/eth/v1/beacon/blobs/{block_id}", Self::blobs::<P>)
            .get(
                "/eth/v1/beacon/execution_payload_envelopes/{block_id}",
                Self::envelope::<P>,
            )
            .post("/eth/v2/beacon/blocks", Self::publish::<P>)
            .post(
                "/eth/v1/beacon/execution_payload_envelopes",
                Self::publish_envelope::<P>,
            )
    }

    /// Genesis time, validators root, and fork version: what a signer needs to compute domains.
    async fn genesis<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        context
            .query(|chain| {
                // Every state carries the genesis fields unchanged, so the head's will do.
                let head = chain.head().root;
                let state = chain
                    .state(&head)
                    .ok_or_else(|| ApiError::not_found("no head state"))?;
                let beacon = state.beacon();
                Ok(Reply::data(
                    Json::from([
                        ("genesis_time", Reply::number(beacon.genesis_time())),
                        (
                            "genesis_validators_root",
                            Reply::text(&beacon.genesis_validators_root()),
                        ),
                        (
                            "genesis_fork_version",
                            Reply::text(&chain.config().genesis_fork_version),
                        ),
                    ]),
                    None,
                ))
            })
            .await
    }

    /// Headers of the blocks at a slot, or of the children of a parent; the head's by default.
    ///
    /// A slot lists its canonical block and every competing block the fork choice holds.
    async fn headers<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let query = Query::of(&request);
        let slot = query.one::<u64>("slot")?.map(Slot);
        let parent: Option<BlockId> = query
            .one::<String>("parent_root")?
            .map(|text| text.parse())
            .transpose()?;
        let parent = match parent {
            None => None,
            Some(BlockId::Root(root)) => Some(root),
            Some(_) => return Err(ApiError::bad_request("parent_root must be a block root")),
        };
        context
            .query(move |chain| {
                let blocks = chain.store().blocks();
                let mut roots: BTreeSet<Root> = BTreeSet::new();
                match (slot, parent) {
                    (None, None) => {
                        roots.insert(chain.head().root);
                    }
                    (slot, parent) => {
                        if let Some(slot) = slot
                            && let Some(root) = chain.canonical_root(slot)?
                        {
                            roots.insert(root);
                        }
                        roots.extend(blocks.iter().filter_map(|(root, node)| {
                            let at_slot = slot.is_none_or(|slot| node.slot == slot);
                            let of_parent = parent.is_none_or(|parent| node.parent_root == parent);
                            (at_slot && of_parent).then_some(*root)
                        }));
                    }
                }
                let mut data = Vec::new();
                let mut freshness = Freshness {
                    execution_optimistic: false,
                    finalized: true,
                };
                for root in roots {
                    let Some(block) = chain.block(root)? else {
                        continue;
                    };
                    // The flags of a list hold for every item: optimistic if any is, finalized if all are.
                    let item = ApiContext::freshness(chain, root, block.slot());
                    freshness.execution_optimistic |= item.execution_optimistic;
                    freshness.finalized &= item.finalized;
                    data.push(Self::header_json(chain, root, &block)?);
                }
                Ok(Reply::data(Json::Array(data), Some(freshness)))
            })
            .await
    }

    /// A block's header and whether it is canonical.
    async fn header<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let id = BlockId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let data = Self::header_json(chain, root, &block)?;
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.slot())),
                ))
            })
            .await
    }

    /// The header object the header routes list.
    fn header_json<P: Preset>(
        chain: &Chain<P>,
        root: Root,
        block: &SignedBeaconBlock<P>,
    ) -> Result<Json, ApiError> {
        let header = block.message().header();
        let canonical = chain.canonical_root(header.slot)? == Some(root);
        Ok(Json::from([
            ("root", Reply::text(&root)),
            ("canonical", canonical.into()),
            (
                "header",
                Json::from([
                    ("message", header.to_json()),
                    ("signature", Reply::text(block.signature())),
                ]),
            ),
        ]))
    }

    /// The root of a block.
    async fn block_root<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let id = BlockId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let data = Json::from([("root", Reply::text(&root))]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.slot())),
                ))
            })
            .await
    }

    /// A whole signed block, as JSON or SSZ.
    async fn block<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let id = BlockId::from_request(&request)?;
        let (block, freshness) = Self::find(&context, id).await?;
        Ok(Reply::object(
            encoding,
            block.fork_name(),
            Some(freshness),
            || block.to_json(),
            || block.encode(),
        ))
    }

    /// A whole signed block with its payload replaced by the payload's header, as JSON or SSZ.
    ///
    /// The header commits to the payload field by field, so the block root and signature carry over.
    /// Blocks without a payload, before Bellatrix and from Gloas on, read the same blinded or not.
    async fn blinded_block<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let id = BlockId::from_request(&request)?;
        let (block, freshness) = Self::find(&context, id).await?;
        let fork = block.fork_name();
        let reply = match SignedBlindedBeaconBlock::blinding(&block) {
            Some(blinded) => Reply::object(
                encoding,
                fork,
                Some(freshness),
                || blinded.to_json(),
                || blinded.encode(),
            ),
            None => Reply::object(
                encoding,
                fork,
                Some(freshness),
                || block.to_json(),
                || block.encode(),
            ),
        };
        Ok(reply)
    }

    /// The attestations a block carries, in its fork's attestation format, as JSON.
    ///
    /// The list sits at the same place in every fork's body, so it is read from the block's JSON.
    async fn attestations<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let id = BlockId::from_request(&request)?;
        let (block, freshness) = Self::find(&context, id).await?;
        let fork = block.fork_name();
        let attestations = block
            .to_json()
            .get("message")
            .and_then(|message| message.get("body"))
            .and_then(|body| body.get("attestations"))
            .cloned()
            .unwrap_or_else(|| Json::Array(Vec::new()));
        Ok(Reply::object(
            Encoding::Json,
            fork,
            Some(freshness),
            || attestations,
            Vec::new,
        ))
    }

    /// A block and its freshness, or a 404.
    async fn find<P: Preset>(
        context: &ApiContext<P>,
        id: BlockId,
    ) -> Result<(SignedBeaconBlock<P>, Freshness), ApiError> {
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((block, freshness))
            })
            .await
    }

    /// The blob sidecars of a Deneb or Electra block, optionally by index.
    async fn blob_sidecars<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let id = BlockId::from_request(&request)?;
        let indices: Vec<u64> = Query::of(&request)
            .list("indices")
            .into_iter()
            .map(|text| {
                text.parse()
                    .map_err(|_| ApiError::bad_request(format!("invalid blob index: {text}")))
            })
            .collect::<Result<_, _>>()?;
        let (sidecars, fork, freshness) = context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let count = block.message().blob_kzg_commitments().len() as u64;
                let wanted: Vec<u64> = if indices.is_empty() {
                    (0..count).collect()
                } else {
                    indices.into_iter().filter(|index| *index < count).collect()
                };
                let mut sidecars = Vec::with_capacity(wanted.len());
                for index in wanted {
                    let sidecar = chain
                        .database()
                        .blob(root, BlobIndex(index))?
                        .ok_or_else(|| ApiError::not_found(format!("blob {index} is not held")))?;
                    sidecars.push(sidecar);
                }
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((sidecars, block.fork_name(), freshness))
            })
            .await?;
        Ok(Reply::sequence::<BlobSidecar<P>>(
            encoding,
            fork,
            Some(freshness),
            &sidecars,
        ))
    }

    /// The blobs of a block, from its sidecars or, from Fulu on, its first half of columns.
    ///
    /// The first half of an extended blob's cells is the blob itself.
    /// So a node holding those columns rebuilds every blob without any proof work.
    /// See the Fulu data availability sampling spec.
    async fn blobs<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let id = BlockId::from_request(&request)?;
        let wanted: Vec<VersionedHash> = Query::of(&request)
            .list("versioned_hashes")
            .into_iter()
            .map(|text| {
                <[u8; 32]>::from_data(text)
                    .map(VersionedHash)
                    .map_err(|_| ApiError::bad_request(format!("invalid versioned hash: {text}")))
            })
            .collect::<Result<_, _>>()?;
        let (blobs, fork, freshness) = context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let fork = block.fork_name();
                let mut commitments: Vec<KzgCommitment> =
                    block.message().blob_kzg_commitments().to_vec();
                // A Gloas block commits to its blobs through its bid.
                if let Some(bid) = chain.payload_bid(&root) {
                    commitments.extend(bid.blob_kzg_commitments.iter().copied());
                }
                let mut blobs = Self::held_blobs(chain, root, fork, commitments.len())?;
                if !wanted.is_empty() {
                    blobs = blobs
                        .into_iter()
                        .zip(&commitments)
                        .filter(|(_, commitment)| wanted.contains(&commitment.versioned_hash()))
                        .map(|(blob, _)| blob)
                        .collect();
                }
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((blobs, fork, freshness))
            })
            .await?;
        // The blobs route carries no version; only the freshness flags sit beside the data.
        Ok(match encoding {
            Encoding::Ssz => Reply::sequence::<Blob<P>>(encoding, fork, Some(freshness), &blobs),
            Encoding::Json => {
                let data = Json::Array(blobs.iter().map(ApiJson::to_json).collect());
                Reply::data(data, Some(freshness))
            }
        })
    }

    /// Every blob of a block the node can rebuild from what it stores.
    fn held_blobs<P: Preset>(
        chain: &Chain<P>,
        root: Root,
        fork: ForkName,
        count: usize,
    ) -> Result<Vec<Blob<P>>, ApiError> {
        let database = chain.database();
        if matches!(
            fork.blob_data(),
            BlobData::BlockColumns | BlobData::PayloadColumns
        ) {
            // Columns 0 to 63 hold the blobs; any missing column means no blob can be rebuilt.
            let half = P::NUMBER_OF_COLUMNS / 2;
            let mut blobs = vec![Vec::with_capacity(P::BytesPerBlob::LEN); count];
            for index in 0..half {
                let column = database
                    .column(root, ColumnIndex(index), fork)?
                    .ok_or_else(|| {
                        ApiError::not_found(format!(
                            "column {index} is not custodied, so blobs cannot be rebuilt"
                        ))
                    })?;
                for (blob, cell) in blobs.iter_mut().zip(column.cells()) {
                    blob.extend_from_slice(cell);
                }
            }
            return blobs
                .into_iter()
                .map(|bytes| {
                    Blob::<P>::decode(&bytes).map_err(|error| {
                        ApiError::internal(format!("malformed column cells: {error}"))
                    })
                })
                .collect();
        }
        (0..count as u64)
            .map(|index| {
                database
                    .blob(root, BlobIndex(index))?
                    .map(|sidecar| sidecar.blob)
                    .ok_or_else(|| ApiError::not_found(format!("blob {index} is not held")))
            })
            .collect()
    }

    /// The payload envelope a Gloas block's builder revealed.
    async fn envelope<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let id = BlockId::from_request(&request)?;
        let (envelope, fork, freshness) = context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let envelope = chain.database().envelope(root)?.ok_or_else(|| {
                    ApiError::not_found(format!("no payload envelope for {root}"))
                })?;
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((envelope, block.fork_name(), freshness))
            })
            .await?;
        Ok(Reply::typed(encoding, fork, Some(freshness), &envelope))
    }

    /// Publishes a block a validator proposed, with its blobs, as JSON or SSZ.
    ///
    /// # Overview
    ///
    /// | outcome                                  | status |
    /// |------------------------------------------|--------|
    /// | broadcast and imported                   | 200    |
    /// | broadcast, but this node's import failed | 202    |
    /// | body neither JSON nor SSZ                | 415    |
    /// | malformed, wrong blob data, or invalid   | 400    |
    async fn publish<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::of_body(&request, true)?;
        let proposal = Self::proposal(&context, &request, encoding).await?;
        match context.publisher.publish(proposal).await {
            Ok(Published::Imported(_)) => Ok(Response::new(StatusCode::OK)),
            Ok(Published::BroadcastOnly(error)) => {
                warn!(%error, "published block was broadcast but not imported");
                Ok(Response::new(StatusCode::ACCEPTED))
            }
            Err(PublishError::ChainStopped) => Err(ChainStopped.into()),
            Err(error) => Err(ApiError::bad_request(error.to_string())),
        }
    }

    /// Publishes a Gloas payload envelope its block's builder revealed, as JSON or SSZ.
    ///
    /// # Overview
    ///
    /// Two headers are required: the consensus version, and whether blob data is included.
    /// This node takes the signed envelope alone, so a body announced with blob data is refused.
    ///
    /// The envelope passes the gossip rules before it is broadcast, the default validation level.
    /// The consensus levels need a full import before the broadcast, which this node does not do.
    /// So a request for them is refused rather than silently weakened.
    ///
    /// Statuses follow the block route: 200 imported, 202 broadcast only, 400 invalid.
    /// See `publishExecutionPayloadEnvelope` in the beacon API.
    async fn publish_envelope<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Self::check_envelope_request(&request)?;
        let encoding = Encoding::of_body(&request, true)?;
        let envelope = match encoding {
            Encoding::Ssz => SignedExecutionPayloadEnvelope::<P>::decode(&request.body)
                .map_err(|error| ApiError::bad_request(format!("malformed envelope: {error}")))?,
            Encoding::Json => ApiJson::from_json(&Self::json_body(&request)?)?,
        };
        match context.publisher.publish_envelope(envelope).await {
            Ok(Published::Imported(_)) => Ok(Response::new(StatusCode::OK)),
            Ok(Published::BroadcastOnly(error)) => {
                warn!(%error, "published envelope was broadcast but not imported");
                Ok(Response::new(StatusCode::ACCEPTED))
            }
            Err(PublishError::ChainStopped) => Err(ChainStopped.into()),
            Err(error) => Err(ApiError::bad_request(error.to_string())),
        }
    }

    /// Checks the headers and query of an envelope publication against the beacon API.
    fn check_envelope_request(request: &Request) -> Result<(), ApiError> {
        let named = request
            .headers
            .get("eth-consensus-version")
            .ok_or_else(|| ApiError::bad_request("missing consensus version header"))?;
        let fork = ForkName::from_name(named)
            .ok_or_else(|| ApiError::bad_request(format!("unknown consensus version: {named}")))?;
        if !fork.separates_payloads() {
            return Err(ApiError::bad_request(format!(
                "{fork} blocks carry their payload"
            )));
        }
        match request.headers.get("eth-blob-data-included") {
            Some(value) if value.eq_ignore_ascii_case("false") => {}
            Some(value) if value.eq_ignore_ascii_case("true") => {
                return Err(ApiError::bad_request(
                    "this node takes the signed envelope alone, without blob data",
                ));
            }
            Some(other) => {
                return Err(ApiError::bad_request(format!(
                    "blob data included header is not a boolean: {other}"
                )));
            }
            None => return Err(ApiError::bad_request("missing blob data included header")),
        }
        match Query::of(request).text("broadcast_validation") {
            None | Some("gossip") => Ok(()),
            Some(level @ ("consensus" | "consensus_and_equivocation")) => {
                Err(ApiError::bad_request(format!(
                    "broadcast validation {level} is not supported; gossip is"
                )))
            }
            Some(other) => Err(ApiError::bad_request(format!(
                "unknown broadcast validation: {other}"
            ))),
        }
    }

    /// The proposal in a publish request's body, decoded in the fork it names.
    ///
    /// The fork comes from the consensus version header, or else from the clock.
    /// From Deneb to Fulu a block travels with its blobs; any other block travels alone.
    async fn proposal<P: Preset>(
        context: &ApiContext<P>,
        request: &Request,
        encoding: Encoding,
    ) -> Result<Proposal<P>, ApiError> {
        let named = request.headers.get("eth-consensus-version");
        let fork = match named {
            Some(name) => ForkName::from_name(name).ok_or_else(|| {
                ApiError::bad_request(format!("unknown consensus version: {name}"))
            })?,
            None => {
                context
                    .query(|chain| Ok(chain.config().fork_at(chain.store().current_epoch())))
                    .await?
            }
        };
        let proposal = match encoding {
            Encoding::Ssz => Proposal::<P>::decode(&request.body, fork).map_err(|error| {
                ApiError::bad_request(format!("malformed {fork} block: {error}"))
            })?,
            Encoding::Json => Proposal::<P>::from_json(&Self::json_body(request)?, fork)?,
        };
        // A block must belong to the fork its slot falls in, whatever the header says.
        let slot = proposal.slot();
        let expected = context
            .query(move |chain| Ok(chain.config().fork_at(slot.epoch::<P>())))
            .await?;
        if expected != fork {
            return Err(ApiError::bad_request(format!(
                "block at slot {slot} is in fork {expected}, not {fork}"
            )));
        }
        Ok(proposal)
    }

    /// A request's body parsed as JSON.
    fn json_body(request: &Request) -> Result<Json, ApiError> {
        Json::parse(&request.body)
            .map_err(|error| ApiError::bad_request(format!("malformed JSON body: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use axiom_http::Method;
    use axiom_types::Minimal;

    use super::*;
    use crate::api::fixture::TestApi;

    /// An error reply's body.
    fn error(code: u16, message: &str) -> Json {
        Json::from([
            ("code", Json::from(u64::from(code))),
            ("message", Json::from(message)),
        ])
    }

    /// A request to publish an envelope, with some headers.
    fn publish(path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request {
        headers.iter().fold(
            Request::new(Method::Post, path).with_body("application/octet-stream", body),
            |request, (name, value)| request.with_header(name, *value),
        )
    }

    #[test]
    fn an_envelope_publication_needs_both_headers() {
        let api = TestApi::gloas(8);
        let route = "/eth/v1/beacon/execution_payload_envelopes";
        let both = [
            ("eth-consensus-version", "gloas"),
            ("eth-blob-data-included", "false"),
        ];
        let cases = [
            // The consensus version is required.
            (
                publish(route, &both[1..], vec![1, 2, 3]),
                error(400, "missing consensus version header"),
            ),
            // Fulu blocks carry their payload, so no envelope travels in Fulu.
            (
                publish(
                    route,
                    &[
                        ("eth-consensus-version", "fulu"),
                        ("eth-blob-data-included", "false"),
                    ],
                    vec![1, 2, 3],
                ),
                error(400, "fulu blocks carry their payload"),
            ),
            // The blob data header is required, and this node takes the envelope alone.
            (
                publish(route, &both[..1], vec![1, 2, 3]),
                error(400, "missing blob data included header"),
            ),
            (
                publish(
                    route,
                    &[
                        ("eth-consensus-version", "gloas"),
                        ("eth-blob-data-included", "true"),
                    ],
                    vec![1, 2, 3],
                ),
                error(
                    400,
                    "this node takes the signed envelope alone, without blob data",
                ),
            ),
            // Only gossip validation runs before the broadcast.
            (
                publish(
                    &format!("{route}?broadcast_validation=consensus"),
                    &both,
                    vec![1, 2, 3],
                ),
                error(
                    400,
                    "broadcast validation consensus is not supported; gossip is",
                ),
            ),
            // Three bytes are no envelope.
            (
                publish(route, &both, vec![1, 2, 3]),
                error(
                    400,
                    &format!(
                        "malformed envelope: {}",
                        SignedExecutionPayloadEnvelope::<Minimal>::decode(&[1, 2, 3]).unwrap_err()
                    ),
                ),
            ),
        ];
        for (request, expected) in cases {
            let target = request.target();
            assert_eq!(
                TestApi::parsed(&api.send(request)),
                (StatusCode::BAD_REQUEST, expected),
                "{target}"
            );
        }
    }
}
