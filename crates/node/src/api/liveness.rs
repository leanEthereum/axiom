//! Liveness: whether the node saw a validator act during an epoch.
//!
//! See `getLiveness` in beacon-APIs.

use std::collections::HashSet;

use axiom_beacon_json::{ApiJson, api::Liveness};
use axiom_http::{Request, StatusCode};
use axiom_json::Json;
use axiom_types::{Epoch, Preset, Slot, ValidatorIndex};

use super::{
    ApiContext,
    query::Body,
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::Chain;

/// The liveness route.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LivenessRoutes;

impl LivenessRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes.post("/eth/v1/validator/liveness/{epoch}", Self::liveness::<P>)
    }

    /// Whether each validator of a list was seen acting during an epoch, in the list's order.
    async fn liveness<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let text = request
            .param("epoch")
            .ok_or_else(|| ApiError::bad_request("missing epoch"))?;
        let epoch = Epoch(
            text.parse()
                .map_err(|_| ApiError::bad_request(format!("invalid epoch: {text}")))?,
        );
        let validators: Vec<ValidatorIndex> = Body(&request).json_items()?;
        if validators.is_empty() {
            return Err(ApiError::bad_request("no validator index to check"));
        }
        context
            .query(move |chain| {
                let live = LiveSet::observed(chain, epoch)?;
                let data: Vec<Liveness> = validators
                    .into_iter()
                    .map(|index| Liveness {
                        index,
                        is_live: live.contains(index),
                    })
                    .collect();
                let body = Json::from([("data", data.to_json())]);
                Ok(Reply::json(StatusCode::OK, &body))
            })
            .await
    }
}

/// The validators the node saw act during one epoch.
///
/// # Overview
///
/// A validator is live in an epoch when the node saw, during that epoch, any of:
///
/// - a vote of it alone, targeting the epoch, that passed the gossip rules;
/// - an aggregate it published as aggregator, targeting the epoch;
/// - a vote of it inside an aggregate the operation pool holds, targeting the epoch;
/// - a block it proposed at a slot of the epoch, gossiped or imported;
/// - a sync committee message it signed at a slot of the epoch;
/// - a payload timeliness vote it signed at a slot of the epoch.
///
/// Messages from the network and from this API count alike, since both pass the gossip rules.
/// Votes the node met only inside imported blocks do not count: the fork choice keeps them apart.
///
/// The node remembers these messages for the current and previous epochs only.
/// So only those two epochs are answered, the minimum the API asks for.
/// The answer is subjective: a node that just started, or was cut off, sees fewer validators.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LiveSet(HashSet<ValidatorIndex>);

impl LiveSet {
    /// The validators seen acting during an epoch, the current or the previous.
    ///
    /// Pooled votes are read through the committees of the head's state.
    ///
    /// # Errors
    ///
    /// Fails for any other epoch, which the node cannot answer for.
    pub(crate) fn observed<P: Preset>(
        chain: &mut Chain<P>,
        epoch: Epoch,
    ) -> Result<Self, ApiError> {
        let current = chain.store().current_epoch();
        let previous = Epoch(current.0.saturating_sub(1));
        if epoch > current {
            return Err(ApiError::bad_request(format!(
                "epoch {epoch} is after the current epoch {current}"
            )));
        }
        if epoch < previous {
            return Err(ApiError::bad_request(format!(
                "epoch {epoch} is before the previous epoch {previous}, so its messages are forgotten"
            )));
        }
        let committees = chain.committees_at(epoch)?;
        let in_epoch = |slot: Slot| slot.epoch::<P>() == epoch;
        let seen = chain.seen();
        let mut live = HashSet::new();
        live.extend(
            seen.attestation_validator_epochs
                .iter()
                .chain(&seen.aggregator_epochs)
                .filter(|(target, _)| *target == epoch)
                .map(|(_, validator)| *validator),
        );
        live.extend(
            seen.proposer_slots
                .iter()
                .chain(&seen.payload_attestation_validators)
                .filter(|(slot, _)| in_epoch(*slot))
                .map(|(_, validator)| *validator),
        );
        live.extend(
            seen.sync_message_validator_slots
                .iter()
                .filter(|(slot, _, _)| in_epoch(*slot))
                .map(|(_, validator, _)| *validator),
        );
        live.extend(
            chain
                .store()
                .blocks()
                .iter()
                .filter(|(_, node)| in_epoch(node.slot))
                .map(|(_, node)| node.proposer_index),
        );
        let groups = chain
            .pool()
            .attestations()
            .groups()
            .filter(|group| group.data.target.epoch == epoch);
        for group in groups {
            for (index, votes) in &group.committees {
                let Some(members) = committees.committee(group.data.slot, *index) else {
                    continue;
                };
                for aggregate in votes.aggregates() {
                    live.extend(
                        aggregate
                            .bits
                            .ones()
                            .filter_map(|position| members.get(position).copied()),
                    );
                }
            }
        }
        Ok(Self(live))
    }

    /// Whether a validator was seen acting.
    pub(crate) fn contains(&self, validator: ValidatorIndex) -> bool {
        self.0.contains(&validator)
    }
}
