//! The light client routes: bootstraps, best updates by period, and the latest updates.
//!
//! Each answer is SSZ, tagged with the fork of the data's attested header.
//! See the light client routes of the beacon API.

use std::str::FromStr;

use axiom_http::{Request, Response, StatusCode};
use axiom_json::Data;
use axiom_types::{Preset, Root, Slot};

use super::{
    ApiContext,
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::Chain;

/// Media type of a sequence of SSZ response chunks.
const SSZ: &str = "application/octet-stream";

/// Routes under `/eth/v1/beacon/light_client`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LightClientRoutes;

impl LightClientRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get(
                "/eth/v1/beacon/light_client/bootstrap/{block_root}",
                Self::bootstrap::<P>,
            )
            .get("/eth/v1/beacon/light_client/updates", Self::updates::<P>)
            .get(
                "/eth/v1/beacon/light_client/finality_update",
                Self::finality_update::<P>,
            )
            .get(
                "/eth/v1/beacon/light_client/optimistic_update",
                Self::optimistic_update::<P>,
            )
    }

    /// The bootstrap of a finalized epoch boundary block.
    async fn bootstrap<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::accepts_ssz(&request) {
            return Err(ApiError::not_acceptable());
        }
        let text = request
            .param("block_root")
            .ok_or_else(|| ApiError::bad_request("missing block root"))?;
        let root = <[u8; 32]>::from_data(text)
            .map(Root)
            .map_err(|_| ApiError::bad_request(format!("invalid block root: {text}")))?;
        context
            .query(move |chain| {
                let bootstrap = chain
                    .light_client()
                    .bootstrap(&root)
                    .ok_or_else(|| ApiError::not_found("no bootstrap for the block"))?;
                Ok(Self::reply(
                    chain,
                    bootstrap.context_slot(),
                    bootstrap.encode(),
                ))
            })
            .await
    }

    /// The best updates of consecutive periods, as length-prefixed chunks.
    ///
    /// Each chunk is an 8-byte little-endian length, the fork digest, then the update.
    /// The length counts the digest and the update.
    async fn updates<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::accepts_ssz(&request) {
            return Err(ApiError::not_acceptable());
        }
        let range: PeriodRange = request.query.as_deref().unwrap_or_default().parse()?;
        context
            .query(move |chain| {
                let mut body = Vec::new();
                let server = chain.light_client();
                for update in server.updates_by_range(range.start_period, range.count) {
                    let digest = chain.fork_digest(update.context_slot().epoch::<P>());
                    let payload = update.encode();
                    let length = (digest.0.len() + payload.len()) as u64;
                    body.extend_from_slice(&length.to_le_bytes());
                    body.extend_from_slice(&digest.0);
                    body.extend_from_slice(&payload);
                }
                Ok(Response::new(StatusCode::OK).with_body(SSZ, body))
            })
            .await
    }

    /// The latest update proving finality on the canonical chain.
    async fn finality_update<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::accepts_ssz(&request) {
            return Err(ApiError::not_acceptable());
        }
        context
            .query(|chain| {
                let update = chain
                    .light_client()
                    .latest_finality_update()
                    .ok_or_else(|| ApiError::not_found("no finality update"))?;
                Ok(Self::reply(chain, update.context_slot(), update.encode()))
            })
            .await
    }

    /// The latest update of the canonical chain, without its finality proof.
    async fn optimistic_update<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::accepts_ssz(&request) {
            return Err(ApiError::not_acceptable());
        }
        context
            .query(|chain| {
                let update = chain
                    .light_client()
                    .latest_optimistic_update()
                    .ok_or_else(|| ApiError::not_found("no optimistic update"))?;
                Ok(Self::reply(chain, update.context_slot(), update.encode()))
            })
            .await
    }

    /// An SSZ answer tagged with the fork in force at the data's attested slot.
    fn reply<P: Preset>(chain: &Chain<P>, context_slot: Slot, bytes: Vec<u8>) -> Response {
        let fork = chain.config().fork_at(context_slot.epoch::<P>());
        Reply::ssz(bytes, fork)
    }
}

/// The periods an update request asks for, from its query string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeriodRange {
    /// The first sync committee period.
    start_period: u64,
    /// How many periods.
    count: u64,
}

impl FromStr for PeriodRange {
    type Err = ApiError;

    fn from_str(query: &str) -> Result<Self, Self::Err> {
        let (mut start_period, mut count) = (None, None);
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let number = || {
                value
                    .parse::<u64>()
                    .map_err(|_| ApiError::bad_request(format!("invalid {name}: {value}")))
            };
            match name {
                "start_period" => start_period = Some(number()?),
                "count" => count = Some(number()?),
                // Unknown parameters are ignored, as for every other route.
                _ => {}
            }
        }
        Ok(Self {
            start_period: start_period
                .ok_or_else(|| ApiError::bad_request("missing start_period"))?,
            count: count.ok_or_else(|| ApiError::bad_request("missing count"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_period_range_reads_both_parameters_in_any_order() {
        // Periods 3 to 7, named in either order, with an unknown parameter between.
        let expected = PeriodRange {
            start_period: 3,
            count: 5,
        };
        assert_eq!("start_period=3&count=5".parse(), Ok(expected));
        assert_eq!("count=5&extra=1&start_period=3".parse(), Ok(expected));
    }

    #[test]
    fn a_period_range_without_a_number_is_a_bad_request() {
        // The count is missing, then malformed, then the start is missing.
        assert_eq!(
            "start_period=3".parse::<PeriodRange>(),
            Err(ApiError::bad_request("missing count"))
        );
        assert_eq!(
            "start_period=3&count=five".parse::<PeriodRange>(),
            Err(ApiError::bad_request("invalid count: five"))
        );
        assert_eq!(
            "count=5".parse::<PeriodRange>(),
            Err(ApiError::bad_request("missing start_period"))
        );
    }
}
