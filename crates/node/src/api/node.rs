//! The node namespace: version, health, sync status, identity, and peers.

use std::{
    future::{Ready, ready},
    sync::atomic::Ordering,
};

use axiom_beacon_json::{ApiJson, api::SyncStatus};
use axiom_execution::JsonCodec;
use axiom_http::{Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_types::Preset;

use super::{
    ApiContext,
    query::Query,
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::{
    Chain,
    chain::SYNCING_DISTANCE,
    client_version::{self, VERSION},
    network::PeerRecord,
};

/// Routes under `/eth/v1/node`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NodeRoutes;

impl NodeRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/node/version", Self::version::<P>)
            .get("/eth/v2/node/version", Self::version_v2::<P>)
            .get("/eth/v1/node/peers", Self::peers::<P>)
            .get("/eth/v1/node/peers/{peer_id}", Self::peer::<P>)
            .get("/eth/v1/node/peer_count", Self::peer_count::<P>)
            .get("/eth/v1/node/health", Self::health::<P>)
            .get("/eth/v1/node/syncing", Self::syncing::<P>)
            .get("/eth/v1/node/identity", Self::identity::<P>)
    }

    /// The client's version string.
    fn version<P: Preset>(_context: ApiContext<P>, _request: Request) -> Ready<ApiResult> {
        // Nothing to wait for: the answer is a constant.
        ready(Ok(Reply::data(
            Json::from([("version", VERSION.into())]),
            None,
        )))
    }

    /// The client's version in the engine API's identification format.
    ///
    /// The engine is not asked for its own version, so only the beacon node is reported.
    fn version_v2<P: Preset>(_context: ApiContext<P>, _request: Request) -> Ready<ApiResult> {
        let beacon_node = client_version::ours().to_json();
        ready(Ok(Reply::data(
            Json::from([("beacon_node", beacon_node)]),
            None,
        )))
    }

    /// The peers the node has met, filtered by connection state and direction.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the route table hands every handler its own context and request"
    )]
    fn peers<P: Preset>(context: ApiContext<P>, request: Request) -> Ready<ApiResult> {
        ready(Self::peers_now(&context, &request))
    }

    /// The peer list, built from the latest snapshot.
    fn peers_now<P: Preset>(context: &ApiContext<P>, request: &Request) -> ApiResult {
        let query = Query::of(request);
        let states = query.list("state");
        let directions = query.list("direction");
        for state in &states {
            if !["disconnected", "connecting", "connected", "disconnecting"].contains(state) {
                return Err(ApiError::bad_request(format!(
                    "invalid peer state: {state}"
                )));
            }
        }
        for direction in &directions {
            if !["inbound", "outbound"].contains(direction) {
                return Err(ApiError::bad_request(format!(
                    "invalid peer direction: {direction}"
                )));
            }
        }
        let peers = Self::snapshot(context);
        let data: Vec<Json> = peers
            .iter()
            .filter(|peer| states.is_empty() || states.contains(&Self::state(peer)))
            .filter(|peer| directions.is_empty() || directions.contains(&Self::direction(peer)))
            .map(Self::peer_json)
            .collect();
        let count = data.len() as u64;
        let body = Json::from([
            ("data", Json::Array(data)),
            ("meta", Json::from([("count", Reply::number(count))])),
        ]);
        Ok(Reply::json(StatusCode::OK, &body))
    }

    /// One peer, by its libp2p identifier.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the route table hands every handler its own context and request"
    )]
    fn peer<P: Preset>(context: ApiContext<P>, request: Request) -> Ready<ApiResult> {
        let found = request
            .param("peer_id")
            .ok_or_else(|| ApiError::bad_request("missing peer id"))
            .and_then(|id| {
                Self::snapshot(&context)
                    .iter()
                    .find(|peer| peer.peer_id == id)
                    .map(|peer| Reply::data(Self::peer_json(peer), None))
                    .ok_or_else(|| ApiError::not_found(format!("peer {id} not found")))
            });
        ready(found)
    }

    /// How many peers are in each connection state.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the route table hands every handler its own context and request"
    )]
    fn peer_count<P: Preset>(context: ApiContext<P>, _request: Request) -> Ready<ApiResult> {
        let peers = Self::snapshot(&context);
        let connected = peers.iter().filter(|peer| peer.connected).count() as u64;
        let disconnected = peers.len() as u64 - connected;
        // Connections open and close inside the network task, so no peer is seen halfway.
        ready(Ok(Reply::data(
            Json::from([
                ("disconnected", Reply::number(disconnected)),
                ("connecting", Reply::number(0)),
                ("connected", Reply::number(connected)),
                ("disconnecting", Reply::number(0)),
            ]),
            None,
        )))
    }

    /// The latest published peers; none without a network.
    fn snapshot<P: Preset>(context: &ApiContext<P>) -> Vec<PeerRecord> {
        context
            .identity
            .as_ref()
            .map(|identity| identity.peers.borrow().as_ref().clone())
            .unwrap_or_default()
    }

    /// A peer in the beacon API's form.
    fn peer_json(peer: &PeerRecord) -> Json {
        Json::from([
            ("peer_id", Json::from(peer.peer_id.as_str())),
            // The record a peer was discovered with is not kept per connection.
            ("enr", Json::Null),
            ("last_seen_p2p_address", Json::from(peer.address.as_str())),
            ("state", Json::from(Self::state(peer))),
            ("direction", Json::from(Self::direction(peer))),
        ])
    }

    /// The connection state's name.
    const fn state(peer: &PeerRecord) -> &'static str {
        if peer.connected {
            "connected"
        } else {
            "disconnected"
        }
    }

    /// The connection direction's name.
    const fn direction(peer: &PeerRecord) -> &'static str {
        if peer.outbound { "outbound" } else { "inbound" }
    }

    /// Ready, syncing, or not working.
    ///
    /// - 200: the head is current.
    /// - 206: the node is catching up.
    /// - 503: the chain thread is gone.
    async fn health<P: Preset>(context: ApiContext<P>, _request: Request) -> ApiResult {
        let distance = context.query(|chain| Ok(Self::distance(chain))).await?;
        let status = if distance >= SYNCING_DISTANCE {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };
        Ok(Response::new(status))
    }

    /// How far the head is behind the clock.
    async fn syncing<P: Preset>(context: ApiContext<P>, _request: Request) -> ApiResult {
        let (head, distance) = context
            .query(|chain| Ok((chain.head(), Self::distance(chain))))
            .await?;
        let status = SyncStatus {
            head_slot: head.slot,
            sync_distance: distance,
            is_syncing: distance >= SYNCING_DISTANCE,
            is_optimistic: head.optimistic,
            // The engine is never probed directly, so it is assumed reachable.
            el_offline: false,
        };
        Ok(Reply::data(status.to_json(), None))
    }

    /// The node's network identity: peer id, record, addresses, and metadata.
    fn identity<P: Preset>(context: ApiContext<P>, _request: Request) -> Ready<ApiResult> {
        let Some(identity) = context.identity else {
            return ready(Err(ApiError::not_found("the node runs without a network")));
        };
        let metadata = &identity.metadata;
        let attnets = metadata.attnets.load(Ordering::Relaxed);
        let data = Json::from([
            ("peer_id", Reply::text(&identity.peer_id)),
            (
                "enr",
                identity.enr.as_ref().map(|enr| enr.borrow().clone()).into(),
            ),
            (
                "p2p_addresses",
                Json::from(vec![Reply::text(&identity.p2p_address)]),
            ),
            (
                "discovery_addresses",
                Json::from(
                    identity
                        .discovery_address
                        .iter()
                        .map(Reply::text)
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "metadata",
                Json::from([
                    (
                        "seq_number",
                        Reply::number(metadata.seq_number.load(Ordering::Relaxed)),
                    ),
                    // Bitfields go out as little-endian hex, as SSZ lays them out.
                    ("attnets", attnets.to_le_bytes().to_data().into()),
                    ("syncnets", Reply::text(&"0x00")),
                    (
                        "custody_group_count",
                        Reply::number(metadata.custody_group_count),
                    ),
                ]),
            ),
        ]);
        ready(Ok(Reply::data(data, None)))
    }

    /// Slots between the head and the fork choice clock.
    const fn distance<P: Preset>(chain: &Chain<P>) -> u64 {
        chain.sync_distance()
    }
}
