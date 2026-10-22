//! The registry routes: the validators of a state, with their balance and status.
//!
//! See the state validators routes of beacon-APIs.

use std::collections::{BTreeSet, HashSet};

use axiom_beacon_json::{
    ApiJson,
    api::{ValidatorResponse, ValidatorStatus},
};
use axiom_http::Request;
use axiom_json::Json;
use axiom_types::{
    BlsPubkey, Epoch, Gwei, Preset, ValidatorIndex, accessors::CoreState, phase0::Validator,
};

use super::{
    ApiContext,
    ids::{StateId, ValidatorId},
    query::{Body, Query},
    reply::{ApiError, ApiResult, Reply, Routes},
};

/// Most validator ids the query form takes.
///
/// The body form takes any number; see `getStateValidators` in the beacon API.
const MAX_QUERY_IDS: usize = 64;

/// Routes under `/eth/v1/beacon/states/{state_id}/validators`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RegistryRoutes;

impl RegistryRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get(
                "/eth/v1/beacon/states/{state_id}/validators",
                Self::validators_by_query::<P>,
            )
            .post(
                "/eth/v1/beacon/states/{state_id}/validators",
                Self::validators_by_body::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
                Self::validator::<P>,
            )
    }

    /// Validators of a state, chosen by the id and status query parameters.
    async fn validators_by_query<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let state = StateId::from_request(&request)?;
        let query = Query::of(&request);
        let ids = query.list("id");
        if ids.len() > MAX_QUERY_IDS {
            return Err(ApiError::too_many(format!(
                "{} validator ids in the query, at most {MAX_QUERY_IDS}",
                ids.len()
            )));
        }
        let selection = Selection::parse(&ids, &query.list("status"))?;
        Self::answer(context, state, selection).await
    }

    /// Validators of a state, chosen by the ids and statuses of a JSON body.
    ///
    /// Either list may be absent, null, or empty, which leaves that attribute unfiltered.
    async fn validators_by_body<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let state = StateId::from_request(&request)?;
        let body = Body(&request).json()?;
        if body.as_object().is_none() {
            return Err(ApiError::bad_request("body is not a JSON object"));
        }
        let selection = Selection::parse(
            &Self::names(&body, "ids")?,
            &Self::names(&body, "statuses")?,
        )?;
        Self::answer(context, state, selection).await
    }

    /// One validator of a state, by index or key.
    async fn validator<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let state = StateId::from_request(&request)?;
        let id: ValidatorId = request
            .param("validator_id")
            .ok_or_else(|| ApiError::bad_request("missing validator id"))?
            .parse()?;
        let selection = Selection {
            ids: vec![id],
            statuses: StatusFilter::default(),
        };
        context
            .query(move |chain| {
                let (root, block) = state.find_block(chain)?;
                let found = selection
                    .matches(ApiContext::held_state(chain, root)?)
                    .pop()
                    .ok_or_else(|| ApiError::not_found("validator not found"))?;
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok(Reply::data(found.to_json(), Some(freshness)))
            })
            .await
    }

    /// The selected validators of a state, in registry order.
    async fn answer<P: Preset>(
        context: ApiContext<P>,
        state: StateId,
        selection: Selection,
    ) -> ApiResult {
        context
            .query(move |chain| {
                let (root, block) = state.find_block(chain)?;
                let found = selection.matches(ApiContext::held_state(chain, root)?);
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok(Reply::data(found.to_json(), Some(freshness)))
            })
            .await
    }

    /// The strings of a body member that may be absent, null, or an array of strings.
    fn names(body: &Json, member: &str) -> Result<Vec<String>, ApiError> {
        let Some(value) = body.get(member).filter(|value| !value.is_null()) else {
            return Ok(Vec::new());
        };
        let items = value
            .as_array()
            .ok_or_else(|| ApiError::bad_request(format!("{member} is not an array")))?;
        items
            .iter()
            .enumerate()
            .map(|(position, item)| {
                item.as_str().map(str::to_owned).ok_or_else(|| {
                    ApiError::bad_request(format!("{member} item {position} is not a string"))
                })
            })
            .collect()
    }
}

/// Which validators of a state a request asks for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Selection {
    /// The validators named, every one when empty.
    ids: Vec<ValidatorId>,
    /// The statuses admitted.
    statuses: StatusFilter,
}

impl Selection {
    /// A selection from id and status names.
    ///
    /// # Errors
    ///
    /// Fails on a malformed id or an unknown status.
    fn parse(ids: &[String], statuses: &[String]) -> Result<Self, ApiError> {
        Ok(Self {
            ids: ids.iter().map(|id| id.parse()).collect::<Result<_, _>>()?,
            statuses: StatusFilter::parse(statuses)?,
        })
    }

    /// The validators of a state this selects, in registry order.
    ///
    /// Ids that name no validator are skipped, as the API asks.
    /// Keys are matched in one pass over the registry, whatever their number.
    fn matches<S: CoreState + ?Sized>(&self, state: &S) -> Vec<ValidatorResponse> {
        let validators = state.validators();
        let balances = state.balances();
        let epoch = state.current_epoch();
        let keys: HashSet<BlsPubkey> = self
            .ids
            .iter()
            .filter_map(|id| match id {
                ValidatorId::Pubkey(key) => Some(*key),
                ValidatorId::Index(_) => None,
            })
            .collect();
        let mut chosen: BTreeSet<usize> = self
            .ids
            .iter()
            .filter_map(|id| match id {
                ValidatorId::Index(index) => Some(index.as_usize()),
                ValidatorId::Pubkey(_) => None,
            })
            .filter(|position| *position < validators.len())
            .collect();
        if self.ids.is_empty() {
            chosen.extend(0..validators.len());
        } else if !keys.is_empty() {
            chosen.extend(
                validators
                    .iter()
                    .enumerate()
                    .filter(|(_, validator)| keys.contains(&validator.pubkey))
                    .map(|(position, _)| position),
            );
        }
        chosen
            .into_iter()
            .filter_map(|position| {
                let validator = validators.get(position)?;
                let balance = balances.get(position).copied().unwrap_or_default();
                let status = Standing { validator, balance }.at(epoch);
                self.statuses.admits(status).then(|| ValidatorResponse {
                    index: ValidatorIndex(position as u64),
                    balance,
                    status,
                    validator: validator.clone(),
                })
            })
            .collect()
    }
}

/// The statuses a request admits, every one when empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct StatusFilter(Vec<ValidatorStatus>);

impl StatusFilter {
    /// The statuses some names admit.
    ///
    /// A name is a status, or one of the four groups the API also takes.
    ///
    /// ```text
    ///     pending      pending_initialized, pending_queued
    ///     active       active_ongoing, active_exiting, active_slashed
    ///     exited       exited_unslashed, exited_slashed
    ///     withdrawal   withdrawal_possible, withdrawal_done
    /// ```
    ///
    /// # Errors
    ///
    /// Fails on a name that is neither.
    fn parse(names: &[String]) -> Result<Self, ApiError> {
        let mut admitted = Vec::new();
        for name in names {
            let group = |prefix: &str| {
                ValidatorStatus::ALL
                    .into_iter()
                    .filter(|status| status.as_str().starts_with(prefix))
                    .collect::<Vec<_>>()
            };
            let matching = match name.as_str() {
                "pending" => group("pending_"),
                "active" => group("active_"),
                "exited" => group("exited_"),
                "withdrawal" => group("withdrawal_"),
                other => vec![ValidatorStatus::from_json(&Json::from(other)).map_err(|_| {
                    ApiError::bad_request(format!("invalid validator status: {other}"))
                })?],
            };
            admitted.extend(matching);
        }
        Ok(Self(admitted))
    }

    /// Whether a status passes.
    fn admits(&self, status: ValidatorStatus) -> bool {
        self.0.is_empty() || self.0.contains(&status)
    }
}

/// A registry record with its balance, which together fix its status at an epoch.
#[derive(Clone, Copy, Debug)]
struct Standing<'a> {
    /// The record.
    validator: &'a Validator,
    /// Its balance.
    balance: Gwei,
}

impl Standing<'_> {
    /// The status at an epoch, by the validator status rules the beacon API links.
    ///
    /// The epochs of the record split time into four spans, and each span splits once more.
    ///
    /// ```text
    ///     epoch < activation             pending     initialized if not yet eligible, else queued
    ///     activation <= epoch < exit     active      ongoing with no exit, slashed, else exiting
    ///     exit <= epoch < withdrawable   exited      slashed or unslashed
    ///     withdrawable <= epoch          withdrawal  done at a zero balance, else possible
    /// ```
    fn at(self, epoch: Epoch) -> ValidatorStatus {
        let validator = self.validator;
        if epoch < validator.activation_epoch {
            if validator.activation_eligibility_epoch == Epoch::FAR_FUTURE {
                ValidatorStatus::PendingInitialized
            } else {
                ValidatorStatus::PendingQueued
            }
        } else if epoch < validator.exit_epoch {
            if validator.exit_epoch == Epoch::FAR_FUTURE {
                ValidatorStatus::ActiveOngoing
            } else if validator.slashed {
                ValidatorStatus::ActiveSlashed
            } else {
                ValidatorStatus::ActiveExiting
            }
        } else if epoch < validator.withdrawable_epoch {
            if validator.slashed {
                ValidatorStatus::ExitedSlashed
            } else {
                ValidatorStatus::ExitedUnslashed
            }
        } else if self.balance == Gwei(0) {
            ValidatorStatus::WithdrawalDone
        } else {
            ValidatorStatus::WithdrawalPossible
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_http::StatusCode;
    use axiom_json::Data;

    use super::*;
    use crate::api::fixture::{BALANCE, TestApi, pubkey, validator};

    /// A record with its four epochs, the largest value meaning the far future.
    fn record(
        eligible: u64,
        active: u64,
        exit: u64,
        withdrawable: u64,
        slashed: bool,
    ) -> Validator {
        let epoch = |value| {
            if value == u64::MAX {
                Epoch::FAR_FUTURE
            } else {
                Epoch(value)
            }
        };
        Validator {
            activation_eligibility_epoch: epoch(eligible),
            activation_epoch: epoch(active),
            exit_epoch: epoch(exit),
            withdrawable_epoch: epoch(withdrawable),
            slashed,
            ..Validator::default()
        }
    }

    #[test]
    fn every_status_follows_the_record_at_epoch_ten() {
        // Fixture state: epoch 10, and one record per status and boundary.
        let far = u64::MAX;
        let cases = [
            (
                record(far, far, far, far, false),
                BALANCE,
                "pending_initialized",
            ),
            (record(9, far, far, far, false), BALANCE, "pending_queued"),
            (record(0, 11, far, far, false), BALANCE, "pending_queued"),
            (record(0, 10, far, far, false), BALANCE, "active_ongoing"),
            (record(0, 0, 11, 20, false), BALANCE, "active_exiting"),
            (record(0, 0, 11, 20, true), BALANCE, "active_slashed"),
            (record(0, 0, 10, 20, false), BALANCE, "exited_unslashed"),
            (record(0, 0, 10, 20, true), BALANCE, "exited_slashed"),
            (record(0, 0, 5, 10, true), Gwei(1), "withdrawal_possible"),
            (record(0, 0, 5, 10, false), Gwei(0), "withdrawal_done"),
        ];
        for (validator, balance, expected) in cases {
            let status = Standing {
                validator: &validator,
                balance,
            }
            .at(Epoch(10));
            assert_eq!(status.as_str(), expected, "{validator:?}");
        }
    }

    #[test]
    fn status_groups_admit_their_members_and_unknown_names_fail() {
        let names = |list: &[&str]| {
            list.iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        // A group expands to its members; a full name stands alone.
        assert_eq!(
            StatusFilter::parse(&names(&["exited", "withdrawal_done"])),
            Ok(StatusFilter(vec![
                ValidatorStatus::ExitedUnslashed,
                ValidatorStatus::ExitedSlashed,
                ValidatorStatus::WithdrawalDone,
            ]))
        );
        assert_eq!(
            StatusFilter::parse(&names(&["active"])),
            Ok(StatusFilter(vec![
                ValidatorStatus::ActiveOngoing,
                ValidatorStatus::ActiveExiting,
                ValidatorStatus::ActiveSlashed,
            ]))
        );
        assert_eq!(
            StatusFilter::parse(&names(&["pending_initialized", "retired"])),
            Err(ApiError::bad_request("invalid validator status: retired"))
        );
    }

    /// The registry of the route tests, read at genesis, epoch 0.
    ///
    /// ```text
    ///     0   active_ongoing
    ///     1   pending_initialized, 1 ETH
    ///     2   active_exiting, exit at epoch 5
    ///     3   withdrawal_done, zero balance
    /// ```
    fn registry() -> Vec<(Validator, Gwei)> {
        let far = u64::MAX;
        let mut records = vec![
            (validator(0), BALANCE),
            (record(far, far, far, far, false), Gwei(1_000_000_000)),
            (record(0, 0, 5, 9, false), BALANCE),
            (record(0, 0, 0, 0, false), Gwei(0)),
        ];
        for (index, (record, _)) in records.iter_mut().enumerate() {
            record.pubkey = pubkey(index as u64);
        }
        records
    }

    /// The JSON the routes answer for a validator of the registry.
    fn response(index: u64, status: ValidatorStatus) -> Json {
        let (validator, balance) = registry()[index as usize].clone();
        ValidatorResponse {
            index: ValidatorIndex(index),
            balance,
            status,
            validator,
        }
        .to_json()
    }

    /// A reply about the genesis state, which is finalized and fully validated.
    fn genesis_reply(data: Json) -> Json {
        Json::from([
            ("execution_optimistic", Json::from(false)),
            ("finalized", Json::from(true)),
            ("data", data),
        ])
    }

    #[test]
    fn validators_are_chosen_by_index_key_and_status_in_the_query() {
        let api = TestApi::phase0_with(registry());
        // Index 99, which names no one, the key of validator 2, and index 0.
        // Only active validators pass, so 0 and 2 answer, in registry order.
        let key = pubkey(2).0.to_data();
        let (status, body) = api.get(&format!(
            "/eth/v1/beacon/states/head/validators?id=99,{key}&id=0&status=active"
        ));
        assert_eq!(status, StatusCode::OK);
        let data = Json::Array(vec![
            response(0, ValidatorStatus::ActiveOngoing),
            response(2, ValidatorStatus::ActiveExiting),
        ]);
        assert_eq!(body, genesis_reply(data));

        // No filter at all lists the whole registry.
        let (_, body) = api.get("/eth/v1/beacon/states/genesis/validators");
        let data = Json::Array(vec![
            response(0, ValidatorStatus::ActiveOngoing),
            response(1, ValidatorStatus::PendingInitialized),
            response(2, ValidatorStatus::ActiveExiting),
            response(3, ValidatorStatus::WithdrawalDone),
        ]);
        assert_eq!(body, genesis_reply(data));
    }

    #[test]
    fn validators_are_chosen_by_the_lists_of_a_body() {
        let api = TestApi::phase0_with(registry());
        // Ids 3 and 1, with a null status list, which filters nothing.
        let (status, body) = api.post(
            "/eth/v1/beacon/states/head/validators",
            r#"{"ids":["3","1"],"statuses":null}"#,
        );
        assert_eq!(status, StatusCode::OK);
        let data = Json::Array(vec![
            response(1, ValidatorStatus::PendingInitialized),
            response(3, ValidatorStatus::WithdrawalDone),
        ]);
        assert_eq!(body, genesis_reply(data.clone()));

        // Every validator, filtered by a group and a full status.
        let (_, body) = api.post(
            "/eth/v1/beacon/states/head/validators",
            r#"{"statuses":["pending","withdrawal_done"]}"#,
        );
        assert_eq!(body, genesis_reply(data));
    }

    #[test]
    fn one_validator_is_found_by_index_or_key() {
        let api = TestApi::phase0_with(registry());
        let (status, body) = api.get("/eth/v1/beacon/states/head/validators/3");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            genesis_reply(response(3, ValidatorStatus::WithdrawalDone))
        );
        let key = pubkey(1).0.to_data();
        let (_, body) = api.get(&format!("/eth/v1/beacon/states/head/validators/{key}"));
        assert_eq!(
            body,
            genesis_reply(response(1, ValidatorStatus::PendingInitialized))
        );

        // A key no validator holds is a 404.
        let key = pubkey(9).0.to_data();
        let (status, body) = api.get(&format!("/eth/v1/beacon/states/head/validators/{key}"));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            body,
            Json::parse(r#"{"code":404,"message":"validator not found"}"#).unwrap()
        );
    }

    #[test]
    fn too_many_query_ids_and_bad_names_are_refused() {
        let api = TestApi::phase0_with(registry());
        // 65 ids, one past the limit of the query form.
        let ids: Vec<String> = (0..65).map(|index| index.to_string()).collect();
        let (status, body) = api.get(&format!(
            "/eth/v1/beacon/states/head/validators?id={}",
            ids.join(",")
        ));
        assert_eq!(status.as_u16(), 414);
        assert_eq!(
            body,
            Json::parse(r#"{"code":414,"message":"65 validator ids in the query, at most 64"}"#)
                .unwrap()
        );

        let (status, body) = api.get("/eth/v1/beacon/states/head/validators?status=retired");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            Json::parse(r#"{"code":400,"message":"invalid validator status: retired"}"#).unwrap()
        );
    }
}
