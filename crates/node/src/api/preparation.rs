//! What validators tell the node ahead of their duties: fees, builders, subnets, and selections.
//!
//! See the preparation, subscription, and selection routes of beacon-APIs.

use std::future::{Ready, ready};

use axiom_beacon_json::api::{
    BeaconCommitteeSubscription, ProposerPreparation, SyncCommitteeSubscription,
};
use axiom_bls::{PublicKey, Signature};
use axiom_http::{Request, Response, StatusCode};
use axiom_p2p::eth::GossipKind;
use axiom_ssz::Ssz;
use axiom_types::{
    ForkName, Preset, bellatrix::SignedValidatorRegistrationV1, gloas::SignedProposerPreferences,
    phase0,
};

use super::{
    ApiContext,
    query::Body,
    reply::{ApiError, ApiResult, Failure, Reply, Routes},
};

/// Routes that prepare the node for its validators' coming duties.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PreparationRoutes;

impl PreparationRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .post(
                "/eth/v1/validator/prepare_beacon_proposer",
                Self::prepare_beacon_proposer::<P>,
            )
            .post(
                "/eth/v1/validator/register_validator",
                Self::register_validator::<P>,
            )
            .post(
                "/eth/v1/validator/proposer_preferences",
                Self::proposer_preferences::<P>,
            )
            .post(
                "/eth/v1/validator/beacon_committee_subscriptions",
                Self::beacon_committee_subscriptions::<P>,
            )
            .post(
                "/eth/v1/validator/sync_committee_subscriptions",
                Self::sync_committee_subscriptions::<P>,
            )
            .post(
                "/eth/v1/validator/beacon_committee_selections",
                Self::selections::<P>,
            )
            .post(
                "/eth/v1/validator/sync_committee_selections",
                Self::selections::<P>,
            )
    }

    /// Records the fee recipients validators name for their coming proposals.
    ///
    /// Unknown and inactive validators are accepted too: they may propose at a later epoch.
    /// See `prepareBeaconProposer` in the beacon API.
    async fn prepare_beacon_proposer<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let preparations: Vec<ProposerPreparation> = Body(&request).json_items()?;
        // Fee recipients serve the chain's coming proposals, so the chain must be running.
        context.query(|_| Ok(())).await?;
        context.proposer.prepare(
            preparations
                .into_iter()
                .map(|preparation| (preparation.validator_index, preparation.fee_recipient)),
        );
        Ok(Response::new(StatusCode::OK))
    }

    /// Records the builder registrations validators signed.
    ///
    /// Each registration must carry its key's signature in the application builder domain.
    /// See `verify_registration_signature` in the Bellatrix builder spec.
    async fn register_validator<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let registrations: Vec<SignedValidatorRegistrationV1> = Body(&request).items()?;
        let domain = context
            .query(|chain| Ok(chain.config().application_builder_domain()))
            .await?;
        let mut accepted = Vec::with_capacity(registrations.len());
        for (position, signed) in registrations.into_iter().enumerate() {
            let root = phase0::SigningData::signing_root(&signed.message, domain);
            let valid = PublicKey::from_bytes(&signed.message.pubkey.0)
                .ok()
                .zip(Signature::from_bytes(&signed.signature.0).ok())
                .is_some_and(|(key, signature)| signature.verify(&key, root.as_ref()));
            if !valid {
                return Err(ApiError::bad_request(format!(
                    "registration {position} is not signed by its key"
                )));
            }
            accepted.push(signed);
        }
        context.proposer.register_with_builders(&accepted).await;
        Ok(Response::new(StatusCode::OK))
    }

    /// Checks proposers' signed preferences as gossip would, then broadcasts those that pass.
    ///
    /// # Overview
    ///
    /// The gossip rules check the slot, the dependent block, the proposer, and the signature.
    /// Preferences that pass are remembered by proposal slot and dependent root.
    /// Bids are then checked against them, until their slot is two epochs old.
    /// Any refusal, even one gossip would only ignore, is reported for its item.
    ///
    /// See `submitProposerPreferences` in the beacon API.
    /// See `validate_proposer_preferences_gossip` in the Gloas p2p spec.
    async fn proposer_preferences<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let named = request
            .headers
            .get("eth-consensus-version")
            .ok_or_else(|| ApiError::bad_request("missing consensus version header"))?;
        if ForkName::from_name(named).is_none() {
            return Err(ApiError::bad_request(format!(
                "unknown consensus version: {named}"
            )));
        }
        let submitted: Vec<SignedProposerPreferences> = Body(&request).items()?;
        let now = context.publisher.now_ms();
        let mut failures = Vec::<Failure>::new();
        for (position, signed) in submitted.into_iter().enumerate() {
            let epoch = signed.message.proposal_slot.epoch::<P>();
            let bytes = signed.encode();
            let verdict = context
                .query(move |chain| {
                    chain
                        .validate_gossip(|validator| validator.proposer_preferences(&signed, now))
                        .map_err(|error| ApiError::bad_request(error.to_string()))
                })
                .await;
            match verdict {
                Ok(()) => {
                    context
                        .publisher
                        .gossip(GossipKind::ProposerPreferences, epoch, bytes)
                        .await;
                }
                Err(error) => failures.push((position, error.to_string())),
            }
        }
        Reply::submission(failures)
    }

    /// Accepts attestation committee subscriptions.
    ///
    /// The node joins the attestation subnets of its own identity only.
    /// An aggregator on another subnet still receives the aggregates of its committee.
    /// An aggregator's committee has its subnet votes pooled, so its aggregate is ready to serve.
    /// See `prepareBeaconCommitteeSubnet` in the beacon API.
    async fn beacon_committee_subscriptions<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let subscriptions: Vec<BeaconCommitteeSubscription> = Body(&request).json_items()?;
        // A subscription needs a running chain, whose subnets it would join.
        // Its validator is the node's own, which the monitor may watch.
        context
            .query(move |chain| {
                for subscription in &subscriptions {
                    chain.auto_register(subscription.validator_index);
                    if subscription.is_aggregator {
                        chain.expect_aggregation(subscription.slot, subscription.committee_index);
                    }
                }
                Ok(())
            })
            .await?;
        Ok(Response::new(StatusCode::OK))
    }

    /// Accepts sync committee subscriptions.
    ///
    /// The node joins no sync committee subnet on request, as with attestation subnets.
    /// See `prepareSyncCommitteeSubnets` in the beacon API.
    async fn sync_committee_subscriptions<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let subscriptions: Vec<SyncCommitteeSubscription> = Body(&request).json_items()?;
        context
            .query(move |chain| {
                for subscription in &subscriptions {
                    chain.auto_register(subscription.validator_index);
                }
                Ok(())
            })
            .await?;
        Ok(Response::new(StatusCode::OK))
    }

    /// Refuses selection proof exchanges with a 501.
    ///
    /// Only distributed validator middleware combines partial selection proofs.
    /// A beacon node has no partial proofs to combine, and the API lets it answer so.
    /// See `submitBeaconCommitteeSelections` and `submitSyncCommitteeSelections` in the beacon API.
    fn selections<P: Preset>(_context: ApiContext<P>, _request: Request) -> Ready<ApiResult> {
        // Nothing to wait for: the answer never depends on the request.
        ready(Err(ApiError::not_implemented(
            "selection proofs are combined by distributed validator middleware, not a beacon node",
        )))
    }
}

#[cfg(test)]
mod tests {
    use axiom_beacon_json::ApiJson;
    use axiom_gossip::GossipError;
    use axiom_http::Method;
    use axiom_json::Json;
    use axiom_types::{
        BlsSignature, CommitteeIndex, Domain, Epoch, ExecutionAddress, Slot, ValidatorIndex,
        constants::DOMAIN_PROPOSER_PREFERENCES,
        gloas::ProposerPreferences,
        phase0::AttestationData,
        vote::{CommitteeVote, PayloadClaim},
    };

    use super::*;
    use crate::{
        ChainSettings,
        api::fixture::{TestApi, secret},
    };

    #[test]
    fn fee_recipients_of_unknown_validators_are_accepted() {
        // Validator 99 is not in the registry of 4, yet it may join and propose later.
        let api = TestApi::phase0(4);
        let body = format!(
            r#"[{{"validator_index":"99","fee_recipient":"0x{}"}}]"#,
            "ab".repeat(20)
        );
        assert_eq!(
            api.post("/eth/v1/validator/prepare_beacon_proposer", &body),
            (StatusCode::OK, Json::Null)
        );
    }

    #[test]
    fn subscriptions_decode_as_the_api_defines_them() {
        let api = TestApi::phase0(4);
        let committee = r#"[{"validator_index":"1","committee_index":"0","committees_at_slot":"1","slot":"3","is_aggregator":true}]"#;
        assert_eq!(
            api.post(
                "/eth/v1/validator/beacon_committee_subscriptions",
                committee
            ),
            (StatusCode::OK, Json::Null)
        );
        let sync =
            r#"[{"validator_index":"1","sync_committee_indices":["0","5"],"until_epoch":"256"}]"#;
        assert_eq!(
            api.post("/eth/v1/validator/sync_committee_subscriptions", sync),
            (StatusCode::OK, Json::Null)
        );
        // A subscription without its aggregator flag is no subscription.
        let missing = r#"[{"validator_index":"1","committee_index":"0","committees_at_slot":"1","slot":"3"}]"#;
        let value = Json::parse(missing).unwrap();
        let items = value.as_array().unwrap();
        let reason = BeaconCommitteeSubscription::from_json(&items[0])
            .unwrap_err()
            .to_string();
        assert_eq!(
            api.post("/eth/v1/validator/beacon_committee_subscriptions", missing),
            (
                StatusCode::BAD_REQUEST,
                Json::from([
                    ("code", Json::from(400_u64)),
                    ("message", Json::from(format!("item 0: {reason}"))),
                ])
            )
        );
    }

    /// A vote by the first member of committee 0 of slot 1, unsigned.
    fn first_vote(api: &TestApi) -> CommitteeVote {
        api.run(|chain| {
            let committees = chain.committees_at(Epoch(0)).unwrap();
            let committee = committees.committee(Slot(1), CommitteeIndex(0)).unwrap();
            let mut bits = vec![false; committee.len()];
            bits[0] = true;
            CommitteeVote {
                data: AttestationData {
                    slot: Slot(1),
                    ..AttestationData::default()
                },
                signature: BlsSignature::default(),
                committees: vec![CommitteeIndex(0)],
                bits,
                payload: PayloadClaim::Silent,
            }
        })
    }

    /// Hands a vote to the chain as gossip, and counts the pool after.
    ///
    /// Counting fails on the unsigned vote, after the pool had its say.
    fn gossip(api: &TestApi, vote: CommitteeVote) -> usize {
        api.run(move |chain| {
            let _uncounted = chain.on_gossip_subnet_vote(&vote, PayloadClaim::Silent);
            chain.pool().attestations().len()
        })
    }

    #[test]
    fn gossip_votes_are_pooled_for_local_aggregators_only() {
        // Fixture state: 64 validators at slot 1, so committee 0 of slot 1 has members.
        let api = TestApi::phase0(64);
        api.at_slot(Slot(1));
        let vote = first_vote(&api);

        // No local validator aggregates committee 0, so the pool stays empty.
        assert_eq!(gossip(&api, vote.clone()), 0);

        // An aggregator of committee 0 at slot 1 subscribes; the same vote is now pooled.
        let subscription = r#"[{"validator_index":"5","committee_index":"0","committees_at_slot":"1","slot":"1","is_aggregator":true}]"#;
        assert_eq!(
            api.post(
                "/eth/v1/validator/beacon_committee_subscriptions",
                subscription
            ),
            (StatusCode::OK, Json::Null)
        );
        assert_eq!(gossip(&api, vote), 1);
    }

    #[test]
    fn importing_all_pools_every_gossip_vote() {
        // Fixture state: the same vote, on a chain told to import all, with no aggregator.
        let settings = ChainSettings {
            import_all_attestations: true,
            ..ChainSettings::default()
        };
        let api = TestApi::phase0_settled(64, settings);
        api.at_slot(Slot(1));
        let vote = first_vote(&api);
        assert_eq!(gossip(&api, vote), 1);
    }

    #[test]
    fn selections_belong_to_distributed_validator_middleware() {
        let api = TestApi::phase0(4);
        let expected = Json::parse(
            r#"{"code":501,"message":"selection proofs are combined by distributed validator middleware, not a beacon node"}"#,
        )
        .unwrap();
        for route in [
            "/eth/v1/validator/beacon_committee_selections",
            "/eth/v1/validator/sync_committee_selections",
        ] {
            assert_eq!(
                api.post(route, "[]"),
                (StatusCode::NOT_IMPLEMENTED, expected.clone()),
                "{route}"
            );
        }
    }

    #[test]
    fn proposer_preferences_pass_the_gossip_rules_once() {
        // Fixture state: a Gloas genesis whose zero lookahead makes validator 0 every proposer.
        // The clock is at slot 1, and the preferences are for slot 9, in epoch 1.
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
        let message = ProposerPreferences {
            dependent_root: genesis,
            proposal_slot: Slot(9),
            validator_index: ValidatorIndex(0),
            fee_recipient: ExecutionAddress([0xfe; 20]),
            target_gas_limit: 60_000_000,
        };
        let root = phase0::SigningData::signing_root(&message, domain);
        let signed = SignedProposerPreferences {
            message,
            signature: BlsSignature(secret(0).sign(&root.0).to_bytes()),
        };
        let route = "/eth/v1/validator/proposer_preferences";
        let post = |items: &[&SignedProposerPreferences]| {
            let body = Json::Array(items.iter().map(|item| item.to_json()).collect());
            let request = Request::new(Method::Post, route)
                .with_header("eth-consensus-version", "gloas")
                .with_body("application/json", body.to_string().into_bytes());
            TestApi::parsed(&api.send(request))
        };

        // Sent twice in one list: the first passes, the second was already seen.
        let seen = GossipError::ignore(
            "already seen preferences for this dependent root and proposal slot",
        );
        let expected = Json::from([
            ("code", Json::from(400_u64)),
            (
                "message",
                Json::from("1 of the submitted items were refused"),
            ),
            (
                "failures",
                Json::Array(vec![Json::from([
                    ("index", Json::from(1_u64)),
                    ("message", Json::from(seen.to_string())),
                ])]),
            ),
        ]);
        assert_eq!(
            post(&[&signed, &signed]),
            (StatusCode::BAD_REQUEST, expected)
        );

        // The version header is required.
        let request =
            Request::new(Method::Post, route).with_body("application/json", b"[]".to_vec());
        assert_eq!(
            TestApi::parsed(&api.send(request)),
            (
                StatusCode::BAD_REQUEST,
                Json::parse(r#"{"code":400,"message":"missing consensus version header"}"#)
                    .unwrap()
            )
        );
    }
}
