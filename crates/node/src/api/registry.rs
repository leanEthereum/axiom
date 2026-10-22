//! The validator routes of a state: records, balances, identities, and Gloas builders.
//!
//! A query names validators by index or public key, and may filter by status.
//! The POST forms take the same lists in a JSON body, for lists too long for a URL.

use axiom_beacon_json::ApiJson;
use axiom_http::{Method, Request};
use axiom_json::Json;
use axiom_state_transition::State;
use axiom_types::{BuilderIndex, Preset, ValidatorIndex, accessors::CoreState};

use super::{
    ApiContext,
    encoding::Encoding,
    ids::{StateId, ValidatorId},
    query::Query,
    reply::{ApiError, ApiResult, Reply, Routes},
    status::{BuilderStatus, StatusFilter, ValidatorStatus},
};

/// Most validator ids one request may name, as the beacon API allows a client to bound it.
///
/// Each id costs a registry lookup, so the bound caps the work one request can demand.
const MAX_IDS: usize = 65_536;

/// Routes over a state's validator registry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RegistryRoutes;

impl RegistryRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get(
                "/eth/v1/beacon/states/{state_id}/validators",
                Self::validators::<P>,
            )
            .post(
                "/eth/v1/beacon/states/{state_id}/validators",
                Self::validators::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
                Self::validator::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/validator_balances",
                Self::balances::<P>,
            )
            .post(
                "/eth/v1/beacon/states/{state_id}/validator_balances",
                Self::balances::<P>,
            )
            .post(
                "/eth/v1/beacon/states/{state_id}/validator_identities",
                Self::identities::<P>,
            )
            .post(
                "/eth/v1/beacon/states/{state_id}/builders",
                Self::builders::<P>,
            )
    }

    /// Validator records with their balances and statuses.
    ///
    /// GET reads ids and statuses from the query, POST from a body of the same names.
    async fn validators<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let (ids, statuses) = if request.method == Method::Post {
            let body = Self::body(&request)?;
            (
                Self::strings(body.get("ids"), "ids")?,
                Self::strings(body.get("statuses"), "statuses")?,
            )
        } else {
            let query = Query::of(&request);
            let owned = |name| query.list(name).into_iter().map(str::to_owned).collect();
            (owned("id"), owned("status"))
        };
        let ids = Self::parse_ids(&ids)?;
        let filter = StatusFilter::parse(statuses.iter().map(String::as_str))?;
        let id = StateId::from_request(&request)?;
        let mut view = context.state(id).await?;
        ApiContext::<P>::compute(move || {
            let epoch = view.state.beacon().current_epoch();
            let indices = Self::select(&mut view.state, ids.as_deref());
            let state = view.state.beacon();
            let data = indices
                .into_iter()
                .filter_map(|index| {
                    let validator = state.validators().get(index.0 as usize)?;
                    let balance = state.balances().get(index.0 as usize).copied()?;
                    let status = ValidatorStatus::of(validator, balance, epoch);
                    filter.keeps(status).then(|| {
                        Json::from([
                            ("index", Reply::number(index.0)),
                            ("balance", Reply::number(balance.0)),
                            ("status", Json::from(status.as_str())),
                            ("validator", validator.to_json()),
                        ])
                    })
                })
                .collect();
            Ok(Reply::data(Json::Array(data), Some(view.freshness)))
        })
        .await
    }

    /// One validator's record, by index or public key.
    async fn validator<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let text = request
            .param("validator_id")
            .ok_or_else(|| ApiError::bad_request("missing validator id"))?;
        let validator_id: ValidatorId = text.parse()?;
        let mut view = context.state(StateId::from_request(&request)?).await?;
        let index = validator_id
            .index(&mut view.state)
            .ok_or_else(|| ApiError::not_found(format!("validator {text} not found")))?;
        let state = view.state.beacon();
        let epoch = state.current_epoch();
        let (Some(validator), Some(balance)) = (
            state.validators().get(index.0 as usize),
            state.balances().get(index.0 as usize).copied(),
        ) else {
            return Err(ApiError::not_found(format!("validator {text} not found")));
        };
        let data = Json::from([
            ("index", Reply::number(index.0)),
            ("balance", Reply::number(balance.0)),
            (
                "status",
                Json::from(ValidatorStatus::of(validator, balance, epoch).as_str()),
            ),
            ("validator", validator.to_json()),
        ]);
        Ok(Reply::data(data, Some(view.freshness)))
    }

    /// Validator balances, by index or public key.
    ///
    /// GET reads ids from the query, POST from a body holding a list of them.
    async fn balances<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let ids = Self::request_ids(&request)?;
        let mut view = context.state(StateId::from_request(&request)?).await?;
        ApiContext::<P>::compute(move || {
            let indices = Self::select(&mut view.state, ids.as_deref());
            let balances = view.state.beacon().balances();
            let data = indices
                .into_iter()
                .filter_map(|index| {
                    let balance = balances.get(index.0 as usize)?;
                    Some(Json::from([
                        ("index", Reply::number(index.0)),
                        ("balance", Reply::number(balance.0)),
                    ]))
                })
                .collect();
            Ok(Reply::data(Json::Array(data), Some(view.freshness)))
        })
        .await
    }

    /// Validator keys and activation epochs, by index or public key.
    async fn identities<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let ids = Self::request_ids(&request)?;
        let mut view = context.state(StateId::from_request(&request)?).await?;
        ApiContext::<P>::compute(move || {
            let indices = Self::select(&mut view.state, ids.as_deref());
            let validators = view.state.beacon().validators();
            let data = indices
                .into_iter()
                .filter_map(|index| {
                    let validator = validators.get(index.0 as usize)?;
                    Some(Json::from([
                        ("index", Reply::number(index.0)),
                        ("pubkey", Reply::text(&validator.pubkey)),
                        (
                            "activation_epoch",
                            Reply::number(validator.activation_epoch.0),
                        ),
                    ]))
                })
                .collect();
            Ok(Reply::data(Json::Array(data), Some(view.freshness)))
        })
        .await
    }

    /// Gloas builders with their statuses, by index or public key.
    async fn builders<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let body = Self::body(&request)?;
        let ids = Self::strings(body.get("ids"), "ids")?;
        let statuses = Self::strings(body.get("statuses"), "statuses")?;
        let ids = Self::parse_ids(&ids)?;
        for status in &statuses {
            if !["pending", "active", "exited"].contains(&status.as_str()) {
                return Err(ApiError::bad_request(format!("invalid status: {status}")));
            }
        }
        let view = context.state(StateId::from_request(&request)?).await?;
        let state = view.state.beacon();
        let finalized = state.finalized_checkpoint().epoch;
        let registry = state
            .builders()
            .ok_or_else(|| ApiError::bad_request("the state is before Gloas"))?
            .builders();
        let data = registry
            .iter()
            .enumerate()
            .filter(|(index, builder)| {
                ids.as_ref().is_none_or(|ids| {
                    ids.iter().any(|id| match id {
                        ValidatorId::Index(wanted) => wanted.0 == *index as u64,
                        ValidatorId::Pubkey(key) => *key == builder.pubkey,
                    })
                })
            })
            .filter_map(|(index, builder)| {
                let status = BuilderStatus::of(builder, finalized);
                let kept =
                    statuses.is_empty() || statuses.iter().any(|name| name == status.as_str());
                kept.then(|| {
                    Json::from([
                        ("index", Reply::number(BuilderIndex(index as u64).0)),
                        ("status", Json::from(status.as_str())),
                        ("builder", builder.to_json()),
                    ])
                })
            })
            .collect();
        Ok(Reply::data(Json::Array(data), Some(view.freshness)))
    }

    /// Ids from a GET query or a POST body holding a plain list.
    fn request_ids(request: &Request) -> Result<Option<Vec<ValidatorId>>, ApiError> {
        if request.method == Method::Post {
            // An empty body asks for every validator, like a query without ids.
            if request.body.iter().all(u8::is_ascii_whitespace) {
                return Ok(None);
            }
            let ids = Self::strings(Some(&Self::body(request)?), "body")?;
            Self::parse_ids(&ids)
        } else {
            let query = Query::of(request);
            let ids: Vec<String> = query.list("id").into_iter().map(str::to_owned).collect();
            Self::parse_ids(&ids)
        }
    }

    /// Parses ids; no ids at all means every validator.
    fn parse_ids(ids: &[String]) -> Result<Option<Vec<ValidatorId>>, ApiError> {
        if ids.is_empty() {
            return Ok(None);
        }
        if ids.len() > MAX_IDS {
            return Err(ApiError::bad_request(format!(
                "{} ids exceed the limit of {MAX_IDS}",
                ids.len()
            )));
        }
        ids.iter()
            .map(|id| id.parse())
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// The registry indices ids name, in order and without repeats; every index for no ids.
    ///
    /// Unknown ids are skipped, as the beacon API asks.
    fn select<P: Preset>(state: &mut State<P>, ids: Option<&[ValidatorId]>) -> Vec<ValidatorIndex> {
        let Some(ids) = ids else {
            let count = state.beacon().validators().len() as u64;
            return (0..count).map(ValidatorIndex).collect();
        };
        let mut indices: Vec<ValidatorIndex> =
            ids.iter().filter_map(|id| id.index(state)).collect();
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// A request's JSON body.
    fn body(request: &Request) -> Result<Json, ApiError> {
        Encoding::of_body(request, false)?;
        if request.body.is_empty() {
            return Ok(Json::Null);
        }
        Json::parse(&request.body)
            .map_err(|error| ApiError::bad_request(format!("malformed JSON body: {error}")))
    }

    /// A list of strings, or nothing when absent or null.
    fn strings(json: Option<&Json>, name: &str) -> Result<Vec<String>, ApiError> {
        match json {
            None | Some(Json::Null) => Ok(Vec::new()),
            Some(Json::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ApiError::bad_request(format!("{name} holds a non-string")))
                })
                .collect(),
            Some(other) => Err(ApiError::bad_request(format!(
                "{name} is {}, not an array",
                other.kind()
            ))),
        }
    }
}
