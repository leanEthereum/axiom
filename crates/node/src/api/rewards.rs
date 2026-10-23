//! The rewards routes: what blocks paid their proposers and committees, and what epochs paid attesters.
//!
//! Each answer replays the spec's reward rules on a state the fork choice holds.
//! The chain thread only clones that state; the replay runs on a blocking worker.
//! See the rewards routes of the beacon API.

use axiom_http::Request;
use axiom_json::Json;
use axiom_state_transition::{
    State,
    rewards::{
        AttesterReward, AttesterRewards, BlockRewards, IdealAttesterReward, RewardsError,
        SyncCommitteeReward,
    },
};
use axiom_types::{Epoch, Preset, Root, Slot, ValidatorIndex, combined::SignedBeaconBlock};
use tokio::task;

use super::{
    ApiContext,
    ids::{BlockId, ValidatorId},
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::Chain;

/// Routes under `/eth/v1/beacon/rewards`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RewardsRoutes;

impl RewardsRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/beacon/rewards/blocks/{block_id}", Self::block::<P>)
            .post(
                "/eth/v1/beacon/rewards/attestations/{epoch}",
                Self::attestations::<P>,
            )
            .post(
                "/eth/v1/beacon/rewards/sync_committee/{block_id}",
                Self::sync_committee::<P>,
            )
    }

    /// What a block paid its proposer, by source.
    async fn block<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = BlockId::from_request(&request)?;
        let (parent, block, freshness, config) = context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                // Rewards replay the block, so a block whose payload was pruned cannot be priced.
                let block = block.into_full().ok_or_else(|| {
                    ApiError::not_found("the block's payload was pruned, so it cannot be replayed")
                })?;
                let parent = Self::parent_state(chain, &block)?;
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((parent, block, freshness, chain.config().clone()))
            })
            .await?;
        let rewards =
            Self::off_thread(move || BlockRewards::of_block(parent, &block, &config)).await?;
        let data = Json::from([
            ("proposer_index", Reply::number(rewards.proposer_index.0)),
            ("total", Reply::number(rewards.total().0)),
            ("attestations", Reply::number(rewards.attestations.0)),
            ("sync_aggregate", Reply::number(rewards.sync_aggregate.0)),
            (
                "proposer_slashings",
                Reply::number(rewards.proposer_slashings.0),
            ),
            (
                "attester_slashings",
                Reply::number(rewards.attester_slashings.0),
            ),
        ]);
        Ok(Reply::data(data, Some(freshness)))
    }

    /// What an epoch's votes earned, ideally and per validator.
    ///
    /// The votes of epoch e are paid at the end of epoch e + 1.
    /// The answer needs that epoch to have ended, and its last block's state to be held.
    async fn attestations<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let text = request
            .param("epoch")
            .ok_or_else(|| ApiError::bad_request("missing epoch"))?;
        let epoch = text
            .parse::<u64>()
            .map(Epoch)
            .map_err(|_| ApiError::bad_request(format!("invalid epoch: {text}")))?;
        let ids = ValidatorId::list_from_body(&request.body)?;
        let (state, freshness, config) = context
            .query(move |chain| {
                let (root, slot, state) = Self::paying_state(chain, epoch)?;
                let freshness = ApiContext::freshness(chain, root, slot);
                Ok((state, freshness, chain.config().clone()))
            })
            .await?;
        let (rewards, wanted) = Self::off_thread(move || {
            let mut lookup = state.clone();
            let wanted = Self::resolve(&ids, &mut lookup);
            AttesterRewards::of_epoch(state, &config, epoch).map(|rewards| (rewards, wanted))
        })
        .await?;
        let validators = rewards
            .validators
            .iter()
            .filter(|reward| Self::is_wanted(wanted.as_deref(), reward.validator_index))
            .map(Self::attester_json)
            .collect::<Vec<_>>();
        let ideal = rewards
            .ideal
            .iter()
            .map(Self::ideal_json)
            .collect::<Vec<_>>();
        let data = Json::from([
            ("ideal_rewards", Json::from(ideal)),
            ("total_rewards", Json::from(validators)),
        ]);
        Ok(Reply::data(data, Some(freshness)))
    }

    /// What a block's sync aggregate paid or charged each committee member.
    async fn sync_committee<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = BlockId::from_request(&request)?;
        let ids = ValidatorId::list_from_body(&request.body)?;
        let (parent, block, freshness, config) = context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                // Rewards replay the block, so a block whose payload was pruned cannot be priced.
                let block = block.into_full().ok_or_else(|| {
                    ApiError::not_found("the block's payload was pruned, so it cannot be replayed")
                })?;
                let parent = Self::parent_state(chain, &block)?;
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok((parent, block, freshness, chain.config().clone()))
            })
            .await?;
        let (rewards, wanted) = Self::off_thread(move || {
            let mut lookup = parent.clone();
            let wanted = Self::resolve(&ids, &mut lookup);
            SyncCommitteeReward::of_block(parent, &block, &config).map(|rewards| (rewards, wanted))
        })
        .await?;
        let data = rewards
            .iter()
            .filter(|reward| Self::is_wanted(wanted.as_deref(), reward.validator_index))
            .map(|reward| {
                Json::from([
                    ("validator_index", Reply::number(reward.validator_index.0)),
                    ("reward", Reply::text(&reward.reward)),
                ])
            })
            .collect::<Vec<_>>();
        Ok(Reply::data(Json::from(data), Some(freshness)))
    }

    /// The post-state of a block's parent, which the block's rewards replay on.
    fn parent_state<P: Preset>(
        chain: &Chain<P>,
        block: &SignedBeaconBlock<P>,
    ) -> Result<State<P>, ApiError> {
        if block.slot() == Slot(0) {
            return Err(ApiError::bad_request("the genesis block pays no rewards"));
        }
        chain
            .state_by_block(block.parent_root())?
            .ok_or_else(|| ApiError::not_found("the parent's state is not held"))
    }

    /// The canonical state at the last slot of the epoch after an epoch, before its transition.
    ///
    /// That is the post-state of the last canonical block at or before the slot.
    ///
    /// # Returns
    ///
    /// The block's root and slot, and its post-state.
    fn paying_state<P: Preset>(
        chain: &Chain<P>,
        epoch: Epoch,
    ) -> Result<(Root, Slot, State<P>), ApiError> {
        let paid_in = epoch.0.saturating_add(1);
        if chain.store().current_epoch().0 <= paid_in {
            return Err(ApiError::not_found(format!(
                "the votes of epoch {epoch} are paid when epoch {paid_in} ends"
            )));
        }
        let last = Slot((paid_in + 1) * P::SLOTS_PER_EPOCH - 1);
        let root = chain
            .canonical_root_at_or_before(last)?
            .ok_or_else(|| ApiError::not_found("no canonical block before the paying slot"))?;
        let slot = chain.block_slot(root)?.unwrap_or(last);
        let state = chain
            .state_by_block(root)?
            .ok_or_else(|| ApiError::not_found("the epoch's state is not held"))?;
        Ok((root, slot, state))
    }

    /// The registry indices of the requested validators, or nothing to mean every validator.
    ///
    /// A validator the state does not know is left out, as filters drop what matches nothing.
    fn resolve<P: Preset>(
        ids: &[ValidatorId],
        state: &mut State<P>,
    ) -> Option<Vec<ValidatorIndex>> {
        (!ids.is_empty()).then(|| ids.iter().filter_map(|id| id.index(state)).collect())
    }

    /// Whether a validator passes the request's filter.
    fn is_wanted(wanted: Option<&[ValidatorIndex]>, index: ValidatorIndex) -> bool {
        wanted.is_none_or(|wanted| wanted.contains(&index))
    }

    /// Runs a reward computation on a blocking worker, so the async runtime keeps serving.
    async fn off_thread<R: Send + 'static>(
        work: impl FnOnce() -> Result<R, RewardsError> + Send + 'static,
    ) -> Result<R, ApiError> {
        match task::spawn_blocking(work).await {
            Ok(Ok(result)) => Ok(result),
            // A block from before Altair has no sync committee to reward.
            Ok(Err(error @ RewardsError::NoSyncCommittee(_))) => {
                Err(ApiError::bad_request(error.to_string()))
            }
            Ok(Err(error)) => Err(ApiError::internal(error.to_string())),
            Err(error) => Err(ApiError::internal(format!(
                "rewards worker failed: {error}"
            ))),
        }
    }

    /// One validator's attestation rewards in the beacon API's JSON form.
    fn attester_json(reward: &AttesterReward) -> Json {
        let mut members = vec![
            ("validator_index", Reply::number(reward.validator_index.0)),
            ("head", Reply::text(&reward.head)),
            ("target", Reply::text(&reward.target)),
            ("source", Reply::text(&reward.source)),
        ];
        // Only phase0 pays for prompt inclusion; later forks leave the member out.
        if let Some(inclusion) = reward.inclusion_delay {
            members.push(("inclusion_delay", Reply::number(inclusion.0)));
        }
        members.push(("inactivity", Reply::text(&reward.inactivity)));
        Json::Object(members.into_iter().collect())
    }

    /// The ideal attestation rewards of one effective balance in the beacon API's JSON form.
    fn ideal_json(reward: &IdealAttesterReward) -> Json {
        let mut members = vec![
            (
                "effective_balance",
                Reply::number(reward.effective_balance.0),
            ),
            ("head", Reply::text(&reward.head)),
            ("target", Reply::text(&reward.target)),
            ("source", Reply::text(&reward.source)),
        ];
        if let Some(inclusion) = reward.inclusion_delay {
            members.push(("inclusion_delay", Reply::number(inclusion.0)));
        }
        members.push(("inactivity", Reply::text(&reward.inactivity)));
        Json::Object(members.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use axiom_state_transition::rewards::SignedGwei;
    use axiom_types::Gwei;

    use super::*;

    #[test]
    fn phase0_rewards_carry_the_inclusion_member_and_later_forks_omit_it() {
        // Fixture state: validator 3 earned 10 for its head vote and lost 4 for its target.
        let mut reward = AttesterReward {
            validator_index: ValidatorIndex(3),
            head: SignedGwei(10),
            target: SignedGwei(-4),
            source: SignedGwei(6),
            inclusion_delay: Some(Gwei(2)),
            inactivity: SignedGwei(0),
        };
        assert_eq!(
            RewardsRoutes::attester_json(&reward).to_string(),
            concat!(
                r#"{"validator_index":"3","head":"10","target":"-4","source":"6","#,
                r#""inclusion_delay":"2","inactivity":"0"}"#
            )
        );

        // Mutation: an Altair reward has no inclusion delay component.
        reward.inclusion_delay = None;
        assert_eq!(
            RewardsRoutes::attester_json(&reward).to_string(),
            r#"{"validator_index":"3","head":"10","target":"-4","source":"6","inactivity":"0"}"#
        );
    }

    #[test]
    fn an_empty_filter_keeps_every_validator() {
        // No list keeps validator 5; a list of 1 and 2 drops it.
        assert!(RewardsRoutes::is_wanted(None, ValidatorIndex(5)));
        let wanted = [ValidatorIndex(1), ValidatorIndex(2)];
        assert!(!RewardsRoutes::is_wanted(Some(&wanted), ValidatorIndex(5)));
        assert!(RewardsRoutes::is_wanted(Some(&wanted), ValidatorIndex(2)));
    }
}
