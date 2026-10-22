//! Routes around payloads that travel apart from their blocks, from Gloas on.
//!
//! Builders bid for payloads, proposers state preferences, and a committee votes on timeliness.
//! See the execution payload, proposer preferences, and pool routes of beacon-APIs.

use axiom_beacon_json::ApiJson;
use axiom_builder_client::RelayClient;
use axiom_http::{Request, Response, StatusCode};
use axiom_p2p::eth::GossipKind;
use axiom_ssz::{Length, Ssz};
use axiom_types::{
    ForkName, Preset, Root, Slot,
    gloas::{BuilderPreferencesEntry, MaxBuilderPreferencesEntries, SignedExecutionPayloadBid},
};
use tokio::task;
use tracing::debug;

use super::{
    ApiContext,
    encoding::Encoding,
    query::{Body, Query},
    reply::{ApiError, ApiResult, Failure, Reply, Routes},
};
use crate::{ApiEvent, EventTopic};

/// Routes of the Gloas payload pipeline: bids, preferences, and payload votes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PayloadRoutes;

impl PayloadRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get(
                "/eth/v1/beacon/pool/payload_attestations",
                Self::pooled_payload_attestations::<P>,
            )
            .get(
                "/eth/v1/beacon/proposer_preferences",
                Self::proposer_preferences::<P>,
            )
            .post(
                "/eth/v1/beacon/execution_payload_bids",
                Self::execution_payload_bid::<P>,
            )
            .post(
                "/eth/v1/validator/builder_preferences",
                Self::builder_preferences::<P>,
            )
    }

    /// The pool's payload timeliness votes, the best aggregate of each, as JSON or SSZ.
    ///
    /// The optional slot narrows the list.
    /// See `getPoolPayloadAttestations` in the beacon API.
    async fn pooled_payload_attestations<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let slot = Query::of(&request).optional_number("slot")?.map(Slot);
        let pooled = context
            .query(move |chain| {
                chain
                    .pool()
                    .payload_attestations()
                    .pooled::<P>(slot)
                    .map_err(|error| ApiError::internal(error.to_string()))
            })
            .await?;
        Ok(Reply::sequence(encoding, ForkName::Gloas, None, &pooled))
    }

    /// The signed proposer preferences the node forwarded, for slots still to come.
    ///
    /// The optional slot and dependent root narrow the list, which is ordered by both.
    /// See `getProposerPreferences` in the beacon API.
    async fn proposer_preferences<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let encoding = Encoding::accepted(&request, true)?;
        let query = Query::of(&request);
        let slot = query.optional_number("slot")?.map(Slot);
        let dependent_root = query.optional_bytes::<32>("dependent_root")?.map(Root);
        let mut known = context
            .query(move |chain| {
                Ok(chain
                    .seen()
                    .proposer_preferences
                    .iter()
                    .filter(|((proposal_slot, root), _)| {
                        slot.is_none_or(|slot| *proposal_slot == slot)
                            && dependent_root.is_none_or(|wanted| *root == wanted)
                    })
                    .map(|(key, signed)| (*key, signed.clone()))
                    .collect::<Vec<_>>())
            })
            .await?;
        known.sort_by_key(|(key, _)| *key);
        let items: Vec<_> = known.into_iter().map(|(_, signed)| signed).collect();
        Ok(Reply::sequence(encoding, ForkName::Gloas, None, &items))
    }

    /// A builder's signed bid: checked as gossip would, pooled, then broadcast.
    ///
    /// Any refusal, even one gossip would only ignore, is a 400.
    /// See `publishExecutionPayloadBid` in the beacon API.
    /// See `validate_execution_payload_bid_gossip` in the Gloas p2p spec.
    async fn execution_payload_bid<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let fork = Self::version(&request)?;
        let bid = match Encoding::of_body(&request, true)? {
            Encoding::Json => Body(&request).json_item::<SignedExecutionPayloadBid>()?,
            Encoding::Ssz => SignedExecutionPayloadBid::decode(&request.body)
                .map_err(|error| ApiError::bad_request(format!("SSZ body: {error}")))?,
        };
        let now = context.publisher.now_ms();
        let epoch = bid.message.slot.epoch::<P>();
        let bytes = bid.encode();
        context
            .query(move |chain| {
                chain
                    .validate_gossip(|validator| validator.execution_payload_bid(&bid, now))
                    .map_err(|error| ApiError::bad_request(error.to_string()))?;
                let events = chain.api_events();
                if events.wants(EventTopic::ExecutionPayloadBid) {
                    events.publish(ApiEvent::versioned(
                        EventTopic::ExecutionPayloadBid,
                        fork,
                        bid.to_json(),
                    ));
                }
                chain.pool_mut().bids_mut().insert(bid);
                Ok(())
            })
            .await?;
        context
            .publisher
            .gossip(GossipKind::ExecutionPayloadBid, epoch, bytes)
            .await;
        Ok(Response::new(StatusCode::OK))
    }

    /// Proposers' preferences for builders, each submitted to the builder it names.
    ///
    /// # Overview
    ///
    /// 1. The whole body is refused when it is too long, or an entry has an empty URL or auth.
    /// 2. Each entry goes to its builder's preferences endpoint, all at once.
    /// 3. The authentication is forwarded unchanged, so the builder checks what was signed.
    /// 4. Entries a builder refused, or that could not reach it, are reported by position.
    ///
    /// See `submitBuilderPreferences` in the beacon API and in the builder API.
    async fn builder_preferences<P: Preset>(
        _context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let fork = Self::version(&request)?;
        if !fork.separates_payloads() {
            return Err(ApiError::bad_request(format!(
                "builder preferences have no meaning in {fork}"
            )));
        }
        let entries: Vec<BuilderPreferencesEntry> = Body(&request).items()?;
        Self::check_entries(&entries)?;
        let submissions: Vec<_> = entries
            .into_iter()
            .map(|entry| task::spawn(Self::submit(entry)))
            .collect();
        let mut failures = Vec::<Failure>::new();
        for (position, submission) in submissions.into_iter().enumerate() {
            let outcome = submission
                .await
                .unwrap_or_else(|error| Err(format!("submission failed: {error}")));
            if let Err(message) = outcome {
                failures.push((position, message));
            }
        }
        Reply::submission(failures)
    }

    /// Refuses a body whose entries cannot all be submitted: too many, or one incomplete.
    ///
    /// See the length limits of `BuilderPreferencesEntry` in beacon-APIs.
    fn check_entries(entries: &[BuilderPreferencesEntry]) -> Result<(), ApiError> {
        let limit = MaxBuilderPreferencesEntries::LEN;
        if entries.len() > limit {
            return Err(ApiError::bad_request(format!(
                "{} builder preference entries, at most {limit} allowed",
                entries.len()
            )));
        }
        for (position, entry) in entries.iter().enumerate() {
            if entry.url.is_empty() {
                return Err(ApiError::bad_request(format!(
                    "entry {position}: the URL is empty"
                )));
            }
            if entry.auth.message.data.is_empty() {
                return Err(ApiError::bad_request(format!(
                    "entry {position}: the auth data is empty"
                )));
            }
        }
        Ok(())
    }

    /// Submits one entry to its builder, giving the reason it failed.
    async fn submit(entry: BuilderPreferencesEntry) -> Result<(), String> {
        let url =
            String::from_utf8(entry.url.to_vec()).map_err(|_| "the URL is not UTF-8".to_owned())?;
        let client = RelayClient::new(&url).map_err(|error| error.to_string())?;
        let outcome = client
            .submit_builder_preferences(entry.proposer_pubkey, &entry.request())
            .await;
        if let Err(error) = &outcome {
            debug!(%url, proposer = %entry.proposer_pubkey, %error, "builder refused preferences");
        }
        outcome.map_err(|error| error.to_string())
    }

    /// The fork the required version header names.
    fn version(request: &Request) -> Result<ForkName, ApiError> {
        let named = request
            .headers
            .get("eth-consensus-version")
            .ok_or_else(|| ApiError::bad_request("missing consensus version header"))?;
        ForkName::from_name(named)
            .ok_or_else(|| ApiError::bad_request(format!("unknown consensus version: {named}")))
    }
}

#[cfg(test)]
mod tests {
    use axiom_builder_client::mock::MockRelay;
    use axiom_http::Method;
    use axiom_json::Json;
    use axiom_ssz::ByteList;
    use axiom_types::{
        BlsPubkey, BlsSignature, Domain, Epoch, ExecutionAddress, Gwei, Hash32, Minimal,
        ValidatorIndex,
        constants::DOMAIN_PROPOSER_PREFERENCES,
        gloas::{
            BuilderPreferences, BuilderPreferencesRequest, BuilderRequestAuth,
            PayloadAttestationData, PayloadAttestationMessage, ProposerPreferences,
            SignedBuilderRequestAuth, SignedProposerPreferences,
        },
        phase0::SigningData,
    };

    use super::*;
    use crate::api::fixture::{TestApi, secret};

    /// A JSON POST with a consensus version header.
    fn versioned_post(route: &str, version: &str, body: &Json) -> Request {
        Request::new(Method::Post, route)
            .with_header("eth-consensus-version", version)
            .with_body("application/json", body.to_string().into_bytes())
    }

    /// The error body of a 400.
    fn bad_request(message: &str) -> (StatusCode, Json) {
        (
            StatusCode::BAD_REQUEST,
            Json::from([
                ("code", Json::from(400_u64)),
                ("message", Json::from(message)),
            ]),
        )
    }

    /// A Gloas list reply.
    fn gloas_list(items: Vec<Json>) -> (StatusCode, Json) {
        (
            StatusCode::OK,
            Json::from([
                ("version", Json::from("gloas")),
                ("data", Json::Array(items)),
            ]),
        )
    }

    #[test]
    fn pooled_payload_votes_are_served_as_json_and_ssz() {
        // Fixture state: a committee of two seats, both held by validator 0.
        // Validator 0 voted that the payload of block 0x04 at slot 0 arrived.
        let api = TestApi::gloas(8);
        let message = PayloadAttestationMessage {
            validator_index: ValidatorIndex(0),
            data: PayloadAttestationData {
                beacon_block_root: Root([4; 32]),
                slot: Slot(0),
                payload_present: true,
                blob_data_available: true,
            },
            signature: BlsSignature([0xc0; 96]),
        };
        let expected = api.run(move |chain| {
            let pool = chain.pool_mut().payload_attestations_mut();
            pool.insert(&message, &[ValidatorIndex(0); 2]).unwrap();
            pool.pooled::<Minimal>(None).unwrap()
        });
        assert_eq!(expected.len(), 1);

        // JSON: the Gloas version and the one aggregate.
        let route = "/eth/v1/beacon/pool/payload_attestations";
        assert_eq!(api.get(route), gloas_list(vec![expected[0].to_json()]));

        // SSZ: the aggregate's bytes alone, tagged with the fork.
        let request =
            Request::new(Method::Get, route).with_header("accept", "application/octet-stream");
        let response = api.send(request);
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers.get("eth-consensus-version"), Some("gloas"));
        assert_eq!(response.body, expected[0].encode());

        // Another slot holds no vote.
        assert_eq!(api.get(&format!("{route}?slot=1")), gloas_list(Vec::new()));
    }

    #[test]
    fn forwarded_preferences_are_served_back_by_slot_and_root() {
        // Fixture state: a Gloas genesis whose zero lookahead makes validator 0 every proposer.
        // The clock is at slot 1; validator 0 states preferences for slots 9 and 10.
        let api = TestApi::gloas(8);
        api.at_slot(Slot(1));
        let (genesis, domain) = api.run(|chain| {
            let domain = Domain::compute(
                DOMAIN_PROPOSER_PREFERENCES,
                chain.config().fork_version_at(Epoch(1)),
                chain.genesis_validators_root(),
            );
            (chain.head().root, domain)
        });
        let signed = |slot| {
            let message = ProposerPreferences {
                dependent_root: genesis,
                proposal_slot: Slot(slot),
                validator_index: ValidatorIndex(0),
                fee_recipient: ExecutionAddress([0xfe; 20]),
                target_gas_limit: 60_000_000,
            };
            let root = SigningData::signing_root(&message, domain);
            SignedProposerPreferences {
                message,
                signature: BlsSignature(secret(0).sign(&root.0).to_bytes()),
            }
        };
        let (nine, ten) = (signed(9), signed(10));
        let body = Json::Array(vec![ten.to_json(), nine.to_json()]);
        let posted = api.send(versioned_post(
            "/eth/v1/validator/proposer_preferences",
            "gloas",
            &body,
        ));
        assert_eq!(posted.status, StatusCode::OK);

        // Both come back, ordered by slot whatever the order they arrived in.
        let route = "/eth/v1/beacon/proposer_preferences";
        assert_eq!(
            api.get(route),
            gloas_list(vec![nine.to_json(), ten.to_json()])
        );

        // The slot narrows to one; another dependent root to none.
        assert_eq!(
            api.get(&format!("{route}?slot=10")),
            gloas_list(vec![ten.to_json()])
        );
        let other_root = format!("0x{}", "ab".repeat(32));
        assert_eq!(
            api.get(&format!("{route}?dependent_root={other_root}")),
            gloas_list(Vec::new())
        );
    }

    #[test]
    fn a_bid_failing_the_gossip_rules_is_refused_with_their_reason() {
        // Fixture state: no proposer stated preferences, so no bid can match any.
        let api = TestApi::gloas(8);
        api.at_slot(Slot(1));
        let bid = SignedExecutionPayloadBid::default();
        let now = api.now_ms();
        let checked = bid.clone();
        let reason = api
            .run(move |chain| {
                chain.validate_gossip(|validator| validator.execution_payload_bid(&checked, now))
            })
            .unwrap_err();

        // The route gives the rule's own reason, and pools nothing.
        let route = "/eth/v1/beacon/execution_payload_bids";
        let response = api.send(versioned_post(route, "gloas", &bid.to_json()));
        assert_eq!(TestApi::parsed(&response), bad_request(&reason.to_string()));
        let pooled = api.run(|chain| {
            chain
                .pool()
                .bids()
                .best(Slot(0), Root::ZERO, Hash32::ZERO)
                .is_some()
        });
        assert!(!pooled);

        // The version header is required.
        let request = Request::new(Method::Post, route)
            .with_body("application/json", bid.to_json().to_string().into_bytes());
        assert_eq!(
            TestApi::parsed(&api.send(request)),
            bad_request("missing consensus version header")
        );
    }

    #[test]
    fn builder_preferences_reach_each_builder_and_failures_are_indexed() {
        // Fixture state: one mock builder, and a URL nothing listens on.
        let api = TestApi::gloas(8);
        let relay = api.block_on(MockRelay::start()).unwrap();
        let entry = |url: &str, proposer: u8| BuilderPreferencesEntry {
            proposer_pubkey: BlsPubkey([proposer; 48]),
            url: ByteList::try_from(url.as_bytes()).unwrap(),
            auth: SignedBuilderRequestAuth {
                message: BuilderRequestAuth {
                    data: ByteList::try_from(b"builder.local".as_slice()).unwrap(),
                    slot: Slot(9),
                },
                signature: BlsSignature([3; 96]),
            },
            max_execution_payment: Gwei(1_000_000_000),
        };
        let reached = entry(relay.url(), 1);
        let unreachable = entry("http://127.0.0.1:1", 2);
        let route = "/eth/v1/validator/builder_preferences";
        let body = Json::Array(vec![reached.to_json(), unreachable.to_json()]);
        let (status, reply) = TestApi::parsed(&api.send(versioned_post(route, "gloas", &body)));

        // Entry 1 failed and is named; entry 0 still reached its builder, auth unchanged.
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let failures = reply.get("failures").and_then(Json::as_array).unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].get("index"), Some(&Json::from(1_u64)));
        assert_eq!(
            relay.builder_preferences(),
            [(
                BlsPubkey([1; 48]),
                BuilderPreferencesRequest {
                    preferences: BuilderPreferences {
                        max_execution_payment: Gwei(1_000_000_000),
                    },
                    auth: reached.auth,
                }
            )]
        );

        // An entry without a URL spoils the whole body, before any builder is called.
        let empty = Json::Array(vec![entry("", 3).to_json()]);
        assert_eq!(
            TestApi::parsed(&api.send(versioned_post(route, "gloas", &empty))),
            bad_request("entry 0: the URL is empty")
        );

        // Before Gloas there are no builder preferences.
        assert_eq!(
            TestApi::parsed(&api.send(versioned_post(route, "fulu", &body))),
            bad_request("builder preferences have no meaning in fulu")
        );
        assert_eq!(relay.builder_preferences().len(), 1);
        api.block_on(relay.stop());
    }
}
