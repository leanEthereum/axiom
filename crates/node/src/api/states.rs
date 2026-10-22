//! The state routes: roots, checkpoints, committees, randomness, and the queues of later forks.
//!
//! Every route here names a state, as a keyword, a slot, or a root.
//! Validator lookups live in their own module.

use axiom_http::Request;
use axiom_json::Json;
use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};
use axiom_state_transition::gloas::ptc::PtcWindow;
use axiom_types::{
    CommitteeIndex, Epoch, Preset, Slot, accessors::CoreState,
    constants::SYNC_COMMITTEE_SUBNET_COUNT, gloas::PayloadTimelinessCommittee, phase0::Checkpoint,
};

use super::{
    ApiContext,
    encoding::Encoding,
    ids::{StateId, StateView},
    query::Query,
    reply::{ApiError, ApiResult, Reply, Routes},
};

/// Routes under `/eth/v1/beacon/states/{state_id}`, validators aside.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StateRoutes;

impl StateRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/beacon/states/{state_id}/root", Self::root::<P>)
            .get("/eth/v1/beacon/states/{state_id}/fork", Self::fork::<P>)
            .get(
                "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
                Self::finality_checkpoints::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/committees",
                Self::committees::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/sync_committees",
                Self::sync_committees::<P>,
            )
            .get("/eth/v1/beacon/states/{state_id}/randao", Self::randao::<P>)
            .get(
                "/eth/v1/beacon/states/{state_id}/pending_deposits",
                Self::pending_deposits::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/pending_partial_withdrawals",
                Self::pending_partial_withdrawals::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/pending_consolidations",
                Self::pending_consolidations::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/proposer_lookahead",
                Self::proposer_lookahead::<P>,
            )
            .get("/eth/v1/beacon/states/{state_id}/ptc", Self::ptc::<P>)
            .get(
                "/eth/v1/beacon/states/{state_id}/builder_pending_withdrawals",
                Self::builder_pending_withdrawals::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/builder_pending_payments",
                Self::builder_pending_payments::<P>,
            )
    }

    /// The state a request's path names.
    async fn view<P: Preset>(
        context: &ApiContext<P>,
        request: &Request,
    ) -> Result<StateView<P>, ApiError> {
        context.state(StateId::from_request(request)?).await
    }

    /// The root of a state.
    async fn root<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let view = Self::view(&context, &request).await?;
        let root = view.state.hash_tree_root();
        Ok(Reply::data(
            Json::from([("root", Reply::text(&root))]),
            Some(view.freshness),
        ))
    }

    /// The fork a state is in.
    async fn fork<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let view = Self::view(&context, &request).await?;
        let fork = view.state.beacon().fork();
        let data = Json::from([
            ("previous_version", Reply::text(&fork.previous_version)),
            ("current_version", Reply::text(&fork.current_version)),
            ("epoch", Reply::number(fork.epoch.0)),
        ]);
        Ok(Reply::data(data, Some(view.freshness)))
    }

    /// The justified and finalized checkpoints a state records.
    async fn finality_checkpoints<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let view = Self::view(&context, &request).await?;
        let state = view.state.beacon();
        let checkpoint = |checkpoint: Checkpoint| {
            Json::from([
                ("epoch", Reply::number(checkpoint.epoch.0)),
                ("root", Reply::text(&checkpoint.root)),
            ])
        };
        let data = Json::from([
            (
                "previous_justified",
                checkpoint(state.previous_justified_checkpoint()),
            ),
            (
                "current_justified",
                checkpoint(state.current_justified_checkpoint()),
            ),
            ("finalized", checkpoint(state.finalized_checkpoint())),
        ]);
        Ok(Reply::data(data, Some(view.freshness)))
    }

    /// The beacon committees of an epoch, optionally narrowed to a slot or an index.
    ///
    /// The epoch defaults to the state's own.
    /// Its seed must already be in the state, and not yet overwritten.
    async fn committees<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let query = Query::of(&request);
        let epoch = query.one::<u64>("epoch")?.map(Epoch);
        let index = query.one::<u64>("index")?.map(CommitteeIndex);
        let slot = query.one::<u64>("slot")?.map(Slot);
        let mut view = Self::view(&context, &request).await?;
        ApiContext::<P>::compute(move || {
            let current = view.state.beacon().current_epoch();
            let epoch = epoch.unwrap_or(current);
            Self::check_seed_epoch::<P>(epoch, current)?;
            if let Some(slot) = slot
                && slot.epoch::<P>() != epoch
            {
                return Err(ApiError::bad_request(format!(
                    "slot {slot} is not in epoch {epoch}"
                )));
            }
            let committees = view.state.compute_committees(epoch);
            let slots = epoch.start_slot::<P>().0..epoch.start_slot::<P>().0 + P::SLOTS_PER_EPOCH;
            let mut data = Vec::new();
            for slot in slots
                .map(Slot)
                .filter(|candidate| slot.is_none_or(|slot| slot == *candidate))
            {
                for committee_index in (0..committees.committees_per_slot())
                    .map(CommitteeIndex)
                    .filter(|candidate| index.is_none_or(|index| index == *candidate))
                {
                    let Some(members) = committees.committee(slot, committee_index) else {
                        continue;
                    };
                    data.push(Json::from([
                        ("index", Reply::number(committee_index.0)),
                        ("slot", Reply::number(slot.0)),
                        (
                            "validators",
                            Json::Array(
                                members
                                    .iter()
                                    .map(|member| Reply::number(member.0))
                                    .collect(),
                            ),
                        ),
                    ]));
                }
            }
            Ok(Reply::data(Json::Array(data), Some(view.freshness)))
        })
        .await
    }

    /// Refuses an epoch whose seed the state does not hold.
    ///
    /// The seed of an epoch mixes the randao of the epoch the lookahead plus one before it.
    /// That mix is final once its epoch ended, and kept for a historical vector of epochs.
    /// See `get_seed` in the phase0 beacon chain spec.
    ///
    /// ```text
    ///     epoch - L - 1 < current                 epoch <= current + L
    ///     epoch - L - 1 > current - VECTOR        epoch >= current + L + 2 - VECTOR
    /// ```
    fn check_seed_epoch<P: Preset>(epoch: Epoch, current: Epoch) -> Result<(), ApiError> {
        let latest = current.0 + P::MIN_SEED_LOOKAHEAD;
        let earliest =
            (current.0 + P::MIN_SEED_LOOKAHEAD + 2).saturating_sub(P::EPOCHS_PER_HISTORICAL_VECTOR);
        if epoch.0 > latest || epoch.0 < earliest {
            return Err(ApiError::bad_request(format!(
                "epoch {epoch} is outside the state's range of {earliest} to {latest}"
            )));
        }
        Ok(())
    }

    /// The sync committee of the current or next period, as indices and subnet slices.
    ///
    /// The epoch defaults to the state's own, and may fall in the next period at most.
    async fn sync_committees<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let epoch = Query::of(&request).one::<u64>("epoch")?.map(Epoch);
        let mut view = Self::view(&context, &request).await?;
        ApiContext::<P>::compute(move || {
            let current = view.state.beacon().current_epoch();
            let epoch = epoch.unwrap_or(current);
            let period = |epoch: Epoch| epoch.0 / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
            let committees = view
                .state
                .beacon()
                .sync_committees()
                .ok_or_else(|| ApiError::bad_request("the state is before Altair"))?;
            let committee = if period(epoch) == period(current) {
                committees.current_sync_committee().clone()
            } else if period(epoch) == period(current) + 1 {
                committees.next_sync_committee().clone()
            } else {
                return Err(ApiError::bad_request(format!(
                    "epoch {epoch} is not in the current or next sync committee period"
                )));
            };
            let mut indices = Vec::with_capacity(committee.pubkeys.len());
            for pubkey in &committee.pubkeys {
                let index = view.state.validator_index(pubkey).ok_or_else(|| {
                    ApiError::internal(format!("sync committee member {pubkey} is not registered"))
                })?;
                indices.push(Reply::number(index.0));
            }
            // Each subnet carries one contiguous slice of the committee.
            // See the Altair validator guide.
            let slice = indices.len() / SYNC_COMMITTEE_SUBNET_COUNT as usize;
            let aggregates = indices
                .chunks(slice.max(1))
                .map(|chunk| Json::Array(chunk.to_vec()))
                .collect();
            let data = Json::from([
                ("validators", Json::Array(indices)),
                ("validator_aggregates", Json::Array(aggregates)),
            ]);
            Ok(Reply::data(data, Some(view.freshness)))
        })
        .await
    }

    /// The randao mix of an epoch the state still holds.
    async fn randao<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let epoch = Query::of(&request).one::<u64>("epoch")?.map(Epoch);
        let view = Self::view(&context, &request).await?;
        let state = view.state.beacon();
        let current = state.current_epoch();
        let epoch = epoch.unwrap_or(current);
        // Mixes of the last historical vector of epochs are kept, the current one included.
        if epoch > current || epoch.0 + P::EPOCHS_PER_HISTORICAL_VECTOR <= current.0 {
            return Err(ApiError::bad_request(format!(
                "epoch {epoch} is outside the state's randao window"
            )));
        }
        let data = Json::from([("randao", Reply::text(&state.randao_mix(epoch)))]);
        Ok(Reply::data(data, Some(view.freshness)))
    }

    /// Deposits waiting to be applied, from Electra on.
    async fn pending_deposits<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = Self::view(&context, &request).await?;
        let queues = view
            .state
            .beacon()
            .pending_queues()
            .ok_or_else(|| ApiError::bad_request("the state is before Electra"))?;
        Ok(Reply::sequence(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            queues.pending_deposits().iter(),
        ))
    }

    /// Partial withdrawals waiting to be swept, from Electra on.
    async fn pending_partial_withdrawals<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = Self::view(&context, &request).await?;
        let queues = view
            .state
            .beacon()
            .pending_queues()
            .ok_or_else(|| ApiError::bad_request("the state is before Electra"))?;
        Ok(Reply::sequence(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            queues.pending_partial_withdrawals().iter(),
        ))
    }

    /// Consolidations waiting to be applied, from Electra on.
    async fn pending_consolidations<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = Self::view(&context, &request).await?;
        let queues = view
            .state
            .beacon()
            .pending_queues()
            .ok_or_else(|| ApiError::bad_request("the state is before Electra"))?;
        Ok(Reply::sequence(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            queues.pending_consolidations().iter(),
        ))
    }

    /// The proposers of the current and next epochs, fixed in advance from Fulu on.
    async fn proposer_lookahead<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = Self::view(&context, &request).await?;
        let lookahead = view
            .state
            .beacon()
            .lookahead()
            .ok_or_else(|| ApiError::bad_request("the state is before Fulu"))?;
        Ok(Reply::sequence(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            lookahead.proposer_lookahead().iter(),
        ))
    }

    /// The payload timeliness committee of a slot, from Gloas on.
    ///
    /// The slot defaults to the state's own, and must lie in the state's committee window.
    async fn ptc<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let slot = Query::of(&request).one::<u64>("slot")?.map(Slot);
        let (view, fork_epoch) = {
            let view = Self::view(&context, &request).await?;
            let fork_epoch = context
                .query(|chain| Ok(chain.config().gloas_fork_epoch))
                .await?;
            (view, fork_epoch)
        };
        let state = view.state.beacon();
        let builders = state
            .builders()
            .ok_or_else(|| ApiError::bad_request("the state is before Gloas"))?;
        let slot = slot.unwrap_or_else(|| state.slot());
        let validators = PtcWindow::of_slot(builders, slot, fork_epoch)
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .clone();
        let assignment = PtcAssignment::<P> { slot, validators };
        let json = || {
            Json::from([
                ("slot", Reply::number(slot.0)),
                (
                    "validators",
                    Json::Array(
                        assignment
                            .validators
                            .iter()
                            .map(|member| Reply::number(member.0))
                            .collect(),
                    ),
                ),
            ])
        };
        Ok(Reply::object(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            json,
            || assignment.encode(),
        ))
    }

    /// Withdrawals owed to builders, from Gloas on.
    async fn builder_pending_withdrawals<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = Self::view(&context, &request).await?;
        let builders = view
            .state
            .beacon()
            .builders()
            .ok_or_else(|| ApiError::bad_request("the state is before Gloas"))?;
        Ok(Reply::sequence(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            builders.builder_pending_withdrawals().iter(),
        ))
    }

    /// Payments owed to builders for the last two epochs, from Gloas on.
    async fn builder_pending_payments<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let view = Self::view(&context, &request).await?;
        let builders = view
            .state
            .beacon()
            .builders()
            .ok_or_else(|| ApiError::bad_request("the state is before Gloas"))?;
        Ok(Reply::sequence(
            encoding,
            view.state.fork_name(),
            Some(view.freshness),
            builders.builder_pending_payments().iter(),
        ))
    }
}

/// A slot and its payload timeliness committee, the SSZ form of the committee route.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PtcAssignment<P: Preset> {
    /// The slot.
    slot: Slot,
    /// The committee members, in committee order.
    validators: PayloadTimelinessCommittee<P>,
}

impl<P: Preset> Container for PtcAssignment<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        <PayloadTimelinessCommittee<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.slot);
        visitor.field(&self.validators);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            slot: fields.field()?,
            validators: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn seed_epochs_span_the_vector_and_the_lookahead() {
        // Minimal: a 64-epoch vector and a lookahead of 1, at current epoch 100.
        // Epoch 39 mixes epoch 37, the oldest mix kept; epoch 101 mixes epoch 99, the last final one.
        let current = Epoch(100);
        assert_eq!(
            StateRoutes::check_seed_epoch::<Minimal>(Epoch(101), current),
            Ok(())
        );
        assert_eq!(
            StateRoutes::check_seed_epoch::<Minimal>(Epoch(39), current),
            Ok(())
        );
        assert_eq!(
            StateRoutes::check_seed_epoch::<Minimal>(Epoch(102), current),
            Err(ApiError::bad_request(
                "epoch 102 is outside the state's range of 39 to 101"
            ))
        );
        assert_eq!(
            StateRoutes::check_seed_epoch::<Minimal>(Epoch(38), current),
            Err(ApiError::bad_request(
                "epoch 38 is outside the state's range of 39 to 101"
            ))
        );
    }
}
