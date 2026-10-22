//! Liveness: whether the node saw a validator act during an epoch.
//!
//! See `getLiveness` in beacon-APIs.

use std::collections::HashSet;

use axiom_beacon_json::{ApiJson, api::Liveness};
use axiom_fork_choice::BlockNode;
use axiom_gossip::Seen;
use axiom_http::{Request, StatusCode};
use axiom_json::Json;
use axiom_operation_pool::VoteGroup;
use axiom_state_transition::EpochCommittees;
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
                "epoch {epoch} is before the previous epoch {previous}, \
                 so its messages are forgotten"
            )));
        }
        let committees = chain.committees_at(epoch)?;
        let blocks = chain.store().blocks().iter().map(|(_, node)| node);
        let groups = chain.pool().attestations().groups();
        Ok(Self::gather::<P>(
            epoch,
            chain.seen(),
            blocks,
            groups,
            &committees,
        ))
    }

    /// The validators some records show acting during an epoch.
    ///
    /// The genesis block has no proposer, so it shows no one.
    fn gather<'a, P: Preset>(
        epoch: Epoch,
        seen: &Seen,
        blocks: impl IntoIterator<Item = &'a BlockNode>,
        groups: impl IntoIterator<Item = &'a VoteGroup>,
        committees: &EpochCommittees,
    ) -> Self {
        let in_epoch = |slot: Slot| slot.epoch::<P>() == epoch;
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
            blocks
                .into_iter()
                .filter(|node| node.slot != Slot(0) && in_epoch(node.slot))
                .map(|node| node.proposer_index),
        );
        let groups = groups
            .into_iter()
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
        Self(live)
    }

    /// Whether a validator was seen acting.
    pub(crate) fn contains(&self, validator: ValidatorIndex) -> bool {
        self.0.contains(&validator)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axiom_fork_choice::{ExecutionStatus, PayloadArrival};
    use axiom_operation_pool::{Aggregate, Bits, CommitteeVotes};
    use axiom_types::{
        BlsSignature, CommitteeIndex, Hash32, Minimal, Root, SubnetId,
        phase0::{self, AttestationData, Checkpoint},
    };

    use super::*;
    use crate::api::fixture::{BALANCE, TestApi, validator};

    /// A fork choice node of a block at a slot, by a proposer.
    fn block(slot: u64, proposer: u64) -> BlockNode {
        BlockNode {
            slot: Slot(slot),
            parent_root: Root::default(),
            proposer_index: ValidatorIndex(proposer),
            parent_block_hash: Hash32::default(),
            execution_block_hash: Hash32::default(),
            status: ExecutionStatus::Valid,
            payload: PayloadArrival::Embedded,
        }
    }

    #[test]
    fn every_kind_of_record_shows_its_validator_live_in_its_epoch_only() {
        // Fixture state: 64 validators, so each minimal slot has 2 committees of 4.
        // Epoch 1 runs from slot 8 to slot 15.
        let mut state = phase0::BeaconState::<Minimal>::default();
        for index in 0..64 {
            state.validators.push(validator(index)).unwrap();
            state.balances.push(BALANCE).unwrap();
        }
        let committees = EpochCommittees::compute(&state, Epoch(1));

        // One record of each kind in epoch 1, and a decoy of the same kind outside it.
        let mut seen = Seen::default();
        let epoch_votes = [(Epoch(1), 1), (Epoch(0), 21)];
        for (epoch, index) in epoch_votes {
            seen.attestation_validator_epochs
                .insert((epoch, ValidatorIndex(index)));
        }
        seen.aggregator_epochs.insert((Epoch(1), ValidatorIndex(3)));
        seen.aggregator_epochs
            .insert((Epoch(2), ValidatorIndex(23)));
        seen.proposer_slots.insert((Slot(9), ValidatorIndex(4)));
        seen.proposer_slots.insert((Slot(16), ValidatorIndex(24)));
        seen.payload_attestation_validators
            .insert((Slot(15), ValidatorIndex(6)));
        seen.payload_attestation_validators
            .insert((Slot(7), ValidatorIndex(26)));
        seen.sync_message_validator_slots
            .insert((Slot(8), ValidatorIndex(7), SubnetId(0)));
        seen.sync_message_validator_slots
            .insert((Slot(17), ValidatorIndex(27), SubnetId(1)));
        let blocks = [block(10, 8), block(3, 28)];

        // A pooled aggregate of committee 1 at slot 9, signed by its third member alone.
        // The same aggregate one epoch earlier names no one in epoch 1.
        let members = committees
            .committee(Slot(9), CommitteeIndex(1))
            .unwrap()
            .to_vec();
        let group = |slot: u64, epoch: u64| {
            let mut votes = CommitteeVotes::default();
            votes
                .insert(Aggregate {
                    bits: Bits::single(members.len(), 2),
                    signature: BlsSignature::default(),
                })
                .unwrap();
            VoteGroup {
                data: AttestationData {
                    slot: Slot(slot),
                    index: CommitteeIndex(1),
                    target: Checkpoint {
                        epoch: Epoch(epoch),
                        root: Root::default(),
                    },
                    ..AttestationData::default()
                },
                committees: BTreeMap::from([(CommitteeIndex(1), votes)]),
            }
        };
        let groups = [group(9, 1), group(1, 0)];

        let live = LiveSet::gather::<Minimal>(Epoch(1), &seen, &blocks, &groups, &committees);
        let expected: HashSet<ValidatorIndex> = [1, 3, 4, 6, 7, 8]
            .into_iter()
            .map(ValidatorIndex)
            .chain([members[2]])
            .collect();
        assert_eq!(live, LiveSet(expected));
    }

    #[test]
    fn the_genesis_block_shows_no_proposer() {
        // The genesis node names validator 0 as its proposer, which never acted.
        let state = phase0::BeaconState::<Minimal>::default();
        let committees = EpochCommittees::compute(&state, Epoch(0));
        let live = LiveSet::gather::<Minimal>(
            Epoch(0),
            &Seen::default(),
            &[block(0, 0)],
            &[],
            &committees,
        );
        assert_eq!(live, LiveSet::default());
    }

    #[test]
    fn liveness_answers_the_current_and_previous_epochs_only() {
        let api = TestApi::phase0(8);
        // At genesis nobody acted yet, and the answer keeps the request's order.
        let (status, body) = api.post("/eth/v1/validator/liveness/0", r#"["1","0"]"#);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            Json::parse(
                r#"{"data":[{"index":"1","is_live":false},{"index":"0","is_live":false}]}"#
            )
            .unwrap()
        );

        // Epoch 1 has not started.
        let (status, body) = api.post("/eth/v1/validator/liveness/1", r#"["0"]"#);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            Json::parse(r#"{"code":400,"message":"epoch 1 is after the current epoch 0"}"#)
                .unwrap()
        );

        // At slot 16 the clock is in epoch 2, so epoch 0 is forgotten and epoch 1 is not.
        api.at_slot(Slot(16));
        let (status, body) = api.post("/eth/v1/validator/liveness/0", r#"["0"]"#);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            Json::parse(
                r#"{"code":400,"message":"epoch 0 is before the previous epoch 1, so its messages are forgotten"}"#
            )
            .unwrap()
        );
        let (status, _) = api.post("/eth/v1/validator/liveness/1", r#"["0"]"#);
        assert_eq!(status, StatusCode::OK);

        // The API asks for at least one index.
        let (status, body) = api.post("/eth/v1/validator/liveness/1", "[]");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            Json::parse(r#"{"code":400,"message":"no validator index to check"}"#).unwrap()
        );
    }
}
