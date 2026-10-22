//! The node namespace: version, health, and sync status.

use std::{
    future::{Ready, ready},
    sync::atomic::Ordering,
};

use axiom_beacon_json::{ApiJson, api::SyncStatus};
use axiom_http::{Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_types::Preset;

use super::{
    ApiContext,
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::Chain;

/// The client's name and version, as reported to peers and tools.
const VERSION: &str = concat!("axiom/v", env!("CARGO_PKG_VERSION"));

/// A head this many slots behind the clock or more means the node is syncing.
///
/// One slot of lag is normal: the current slot's block may not have arrived yet.
const SYNCING_DISTANCE: u64 = 2;

/// Routes under `/eth/v1/node`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NodeRoutes;

impl NodeRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/node/version", Self::version::<P>)
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
        chain
            .store()
            .current_slot()
            .0
            .saturating_sub(chain.head().slot.0)
    }
}
