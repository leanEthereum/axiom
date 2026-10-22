//! The debug namespace: whole states, the fork choice's tree, and stored columns.

use std::collections::HashMap;

use axiom_beacon_json::{ApiJson, ForkedJson};
use axiom_fork_choice::{BlockNode, ExecutionStatus, ForkChoiceNode, NodePayload, PayloadArrival};
use axiom_http::Request;
use axiom_json::{Json, Object};
use axiom_types::{
    ColumnIndex, Gwei, Preset, Root, accessors::CoreState, combined::DataColumnSidecar,
    phase0::Checkpoint,
};

use super::{
    ApiContext,
    encoding::Encoding,
    ids::{BlockId, StateId},
    query::Query,
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::Chain;

/// Routes under `/eth/v1/debug` and `/eth/v2/debug`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DebugRoutes;

impl DebugRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v2/debug/beacon/states/{state_id}", Self::state::<P>)
            .get("/eth/v2/debug/beacon/heads", Self::heads::<P>)
            .get("/eth/v1/debug/fork_choice", Self::fork_choice::<P>)
            .get("/eth/v2/debug/fork_choice", Self::fork_choice_v2::<P>)
            .get(
                "/eth/v1/debug/beacon/data_column_sidecars/{block_id}",
                Self::data_column_sidecars::<P>,
            )
    }

    /// A whole state, as JSON or SSZ.
    async fn state<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = context.state(StateId::from_request(&request)?).await?;
        ApiContext::<P>::compute(move || {
            let beacon = view.state.beacon();
            Ok(Reply::object(
                encoding,
                view.state.fork_name(),
                Some(view.freshness),
                || beacon.to_json(),
                || beacon.encode(),
            ))
        })
        .await
    }

    /// Every leaf of the fork choice's block tree: the competing chain tips.
    async fn heads<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        context
            .query(|chain| {
                let blocks = chain.store().blocks();
                // A leaf is a block nothing builds on yet.
                let leaves: Vec<Json> = blocks
                    .iter()
                    .filter(|(root, _)| blocks.children(root).is_empty())
                    .map(|(root, node)| {
                        Json::from([
                            ("root", Reply::text(&root)),
                            ("slot", Reply::number(node.slot.0)),
                            (
                                "execution_optimistic",
                                (node.status != ExecutionStatus::Valid).into(),
                            ),
                        ])
                    })
                    .collect();
                Ok(Reply::data(Json::Array(leaves), None))
            })
            .await
    }

    /// One node per block, with its weight, validity, and checkpoints.
    async fn fork_choice<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        context
            .query(|chain| {
                let weights: HashMap<Root, Gwei> = chain
                    .node_weights()?
                    .into_iter()
                    // A block's weight sits on its only node, or on the pending node of a Gloas block.
                    .filter(|(node, _)| {
                        node.payload == NodePayload::Pending || Self::is_embedded(chain, node)
                    })
                    .map(|(node, weight)| (node.root, weight))
                    .collect();
                let nodes: Vec<Json> = chain
                    .store()
                    .blocks()
                    .iter()
                    .map(|(root, node)| {
                        let (justified, finalized) = Self::checkpoints(chain, root);
                        Json::from([
                            ("slot", Reply::number(node.slot.0)),
                            ("block_root", Reply::text(root)),
                            ("parent_root", Reply::text(&node.parent_root)),
                            ("justified_epoch", Reply::number(justified.epoch.0)),
                            ("finalized_epoch", Reply::number(finalized.epoch.0)),
                            (
                                "weight",
                                Reply::number(weights.get(root).copied().unwrap_or_default().0),
                            ),
                            ("validity", Json::from(Self::validity(node.status))),
                            (
                                "execution_block_hash",
                                Reply::text(&node.execution_block_hash),
                            ),
                            ("extra_data", Json::Object(Object::new())),
                        ])
                    })
                    .collect();
                Ok(Reply::data(Self::dump(chain, nodes), None))
            })
            .await
    }

    /// One node per block and payload status, as the Gloas fork choice weighs them.
    async fn fork_choice_v2<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        context
            .query(|chain| {
                let weights = chain.node_weights()?;
                let blocks = chain.store().blocks();
                let mut nodes = Vec::with_capacity(weights.len());
                for (variant, weight) in weights {
                    let Some(node) = blocks.get(&variant.root) else {
                        continue;
                    };
                    nodes.push(Self::node_v2(chain, variant, node, weight));
                }
                Ok(Reply::data(Self::dump(chain, nodes), None))
            })
            .await
    }

    /// One node of the second fork choice dump.
    fn node_v2<P: Preset>(
        chain: &Chain<P>,
        variant: ForkChoiceNode,
        node: &BlockNode,
        weight: Gwei,
    ) -> Json {
        let blocks = chain.store().blocks();
        let embedded = Self::is_embedded(chain, &variant);
        // A Gloas variant hangs under its own block's pending node.
        let (parent_root, parent_payload) = if variant.payload == NodePayload::Pending || embedded {
            let parent_payload = if blocks.contains(&node.parent_root) {
                blocks
                    .parent_payload(&variant.root)
                    .or(Some(NodePayload::Full))
            } else {
                None
            };
            (node.parent_root, parent_payload)
        } else {
            (variant.root, Some(NodePayload::Pending))
        };
        // A full node commits to its own payload; the others to the payload they build on.
        let execution_block_hash = if variant.payload == NodePayload::Full {
            node.execution_block_hash
        } else {
            node.parent_block_hash
        };
        let (justified, finalized) = Self::checkpoints(chain, &variant.root);
        let votes = chain.store().payload_votes(&variant.root);
        let count = |seats: Option<&Vec<Option<bool>>>, wanted: Option<bool>| {
            seats.map_or(0, |seats| {
                seats
                    .iter()
                    .filter(|seat| {
                        wanted.map_or_else(|| seat.is_some(), |wanted| **seat == Some(wanted))
                    })
                    .count() as u64
            })
        };
        Json::from([
            ("slot", Reply::number(node.slot.0)),
            ("block_root", Reply::text(&variant.root)),
            (
                "payload_status",
                Json::from(Self::payload_name(variant.payload)),
            ),
            ("parent_root", Reply::text(&parent_root)),
            (
                "parent_payload_status",
                parent_payload.map(Self::payload_name).into(),
            ),
            ("justified_checkpoint", justified.to_json()),
            ("finalized_checkpoint", finalized.to_json()),
            ("weight", Reply::number(weight.0)),
            ("validity", Json::from(Self::validity(node.status))),
            ("execution_block_hash", Reply::text(&execution_block_hash)),
            (
                "payload_attester_count",
                Reply::number(count(votes.map(|votes| &votes.timely), None)),
            ),
            (
                "payload_availability_yes_count",
                Reply::number(count(votes.map(|votes| &votes.timely), Some(true))),
            ),
            (
                "payload_data_availability_yes_count",
                Reply::number(count(votes.map(|votes| &votes.available), Some(true))),
            ),
            ("extra_data", Json::Object(Object::new())),
        ])
    }

    /// The store's checkpoints around a list of nodes.
    fn dump<P: Preset>(chain: &Chain<P>, nodes: Vec<Json>) -> Json {
        let store = chain.store();
        Json::from([
            (
                "justified_checkpoint",
                store.justified_checkpoint().to_json(),
            ),
            (
                "finalized_checkpoint",
                store.finalized_checkpoint().to_json(),
            ),
            ("fork_choice_nodes", Json::Array(nodes)),
            ("extra_data", Json::Object(Object::new())),
        ])
    }

    /// Whether a node belongs to a block whose payload rides inside it.
    fn is_embedded<P: Preset>(chain: &Chain<P>, node: &ForkChoiceNode) -> bool {
        chain
            .store()
            .blocks()
            .get(&node.root)
            .is_some_and(|block| block.payload == PayloadArrival::Embedded)
    }

    /// The justified and finalized checkpoints a block's post-state records.
    fn checkpoints<P: Preset>(chain: &Chain<P>, root: &Root) -> (Checkpoint, Checkpoint) {
        chain.state(root).map_or_else(
            || (Checkpoint::default(), Checkpoint::default()),
            |state| {
                let state = state.beacon();
                (
                    state.current_justified_checkpoint(),
                    state.finalized_checkpoint(),
                )
            },
        )
    }

    /// The name the dump gives an execution status.
    const fn validity(status: ExecutionStatus) -> &'static str {
        match status {
            ExecutionStatus::Valid => "valid",
            ExecutionStatus::Optimistic => "optimistic",
            ExecutionStatus::Invalid => "invalid",
        }
    }

    /// The name the dump gives a payload status.
    const fn payload_name(payload: NodePayload) -> &'static str {
        match payload {
            NodePayload::Pending => "pending",
            NodePayload::Empty => "empty",
            NodePayload::Full => "full",
        }
    }

    /// The custody columns the node stores for a block, optionally by index.
    async fn data_column_sidecars<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let id = BlockId::from_request(&request)?;
        let indices: Vec<u64> = Query::of(&request)
            .list("indices")
            .into_iter()
            .map(|text| {
                text.parse()
                    .map_err(|_| ApiError::bad_request(format!("invalid column index: {text}")))
            })
            .collect::<Result<_, _>>()?;
        let (columns, fork, freshness) = context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let fork = block.fork_name();
                let wanted: Vec<ColumnIndex> = if indices.is_empty() {
                    chain.custody().iter().copied().collect()
                } else {
                    indices.into_iter().map(ColumnIndex).collect()
                };
                let mut columns = Vec::new();
                for index in wanted {
                    if let Some(column) = chain.database().column(root, index, fork)? {
                        columns.push(column);
                    }
                }
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((columns, fork, freshness))
            })
            .await?;
        Ok(Reply::object(
            encoding,
            fork,
            Some(freshness),
            || Json::Array(columns.iter().map(ForkedJson::to_json).collect()),
            || Self::list_of_variable(columns.iter().map(DataColumnSidecar::encode)),
        ))
    }

    /// The SSZ list of variable-size items: an offset to each, then the items.
    ///
    /// Each offset counts bytes from the list's start, past the offset table of four bytes per item.
    fn list_of_variable(items: impl Iterator<Item = Vec<u8>>) -> Vec<u8> {
        let items: Vec<Vec<u8>> = items.collect();
        let mut offset = items.len() * 4;
        let mut out = Vec::with_capacity(offset + items.iter().map(Vec::len).sum::<usize>());
        for item in &items {
            // A response this size never reaches 4 GiB; it saturates rather than wraps.
            out.extend_from_slice(&u32::try_from(offset).unwrap_or(u32::MAX).to_le_bytes());
            offset += item.len();
        }
        for item in items {
            out.extend_from_slice(&item);
        }
        out
    }
}
